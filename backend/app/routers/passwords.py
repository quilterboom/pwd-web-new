import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import (
    ensure_group_access,
    get_current_user,
    get_user_group_ids,
    visibility_filter,
)
from ..crypto import entry_cipher, manager
from ..db import get_db
from ..models import Group, History, OrgKey, PasswordEntry, User

router = APIRouter(
    prefix="/api/passwords",
    tags=["passwords"],
    dependencies=[Depends(get_current_user)],
)


class CreateRequest(BaseModel):
    title: Optional[str] = None  # 已取消必填；保留字段仅用于审计/兼容历史
    username: str = ""
    secret: str
    notes: str = ""
    comment: str = ""
    group_id: int  # 必填：数据绑定的分组
    algorithm: str = "symmetric"  # 'symmetric' = 条目密码对称加密；'gpg' / 'sm2' = legacy
    entry_password: str = ""  # algorithm='symmetric' 时必填；其余算法不需要
    orgkey_id: Optional[int] = None  # legacy 方案时使用：选一把本组织 OrgKey 的公钥加密


class UpdateRequest(BaseModel):
    title: Optional[str] = None
    username: Optional[str] = None
    algorithm: Optional[str] = None  # 目标算法：'symmetric' | 'gpg' | 'sm2'（省略则保持原方案）
    secret: Optional[str] = None
    notes: Optional[str] = None
    comment: str = ""
    entry_password: Optional[str] = None  # 当前条目密码（scheme=entry 或目标改 symmetric 时必填）
    new_entry_password: Optional[str] = None  # 仅当目标为 symmetric 时使用（不填则沿用当前/服务端密钥加密）
    orgkey_id: Optional[int] = None  # legacy 方案的目标 OrgKey；省略则保持 / 回退


class UnlockRequest(BaseModel):
    """查看受「解密密码」保护的条目时，用请求体（而非 URL 查询参数）传递解密密码，
    避免密码出现在 URL、服务器访问日志与浏览器历史中。"""
    entry_password: Optional[str] = None


class ExportRequest(BaseModel):
    ids: list[int]  # 要导出的条目 id
    passwords: dict[str, str] = {}  # 明文导出时：{ "<entry_id>": "<解密密码>" }
    format: str = "json"  # 'json' | 'csv'
    plaintext: bool = False  # True=导出明文；False=加密备份（仅含密文，无需密码）


def _serialize_meta(db: Session, e: PasswordEntry) -> dict:
    key_name = None
    if e.orgkey_id:
        k = db.query(OrgKey).filter_by(id=e.orgkey_id).first()
        if k:
            key_name = k.name
    return {
        "id": e.id,
        "title": e.title or "",
        "username": e.username,
        "algorithm": e.algorithm,
        "scheme": e.scheme,
        "needs_password": bool(e.entry_salt) and bool(e.entry_iv),
        "notes": e.notes,
        "group_id": e.group_id,
        "orgkey_id": e.orgkey_id,
        "key_name": key_name,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        "created_by": e.created_by,
        "updated_by": e.updated_by,
    }


def _require_algorithm(algo: Optional[str]) -> Optional[str]:
    if algo is None:
        return None
    if algo not in manager.SUPPORTED:
        raise HTTPException(status_code=400, detail=f"不支持的算法: {algo}")
    return algo


def _resolve_orgkey(db: Session, user: User, orgkey_id: Optional[int], expected_group_id: int) -> Optional[OrgKey]:
    """若传了 orgkey_id：必须在用户可见组织内且与 expected_group_id 相同。"""
    if not orgkey_id:
        return None
    rec = db.query(OrgKey).filter_by(id=orgkey_id).first()
    if rec is None:
        raise HTTPException(status_code=400, detail="指定的 OrgKey 不存在")
    ensure_group_access(db, user, rec.group_id)
    if rec.group_id != expected_group_id:
        raise HTTPException(status_code=400, detail="OrgKey 与数据分组不匹配")
    return rec


def _encrypt_for_create(db: Session, user: User, req: CreateRequest) -> dict:
    """按 algorithm 分流，但无论哪种方式都先以「条目密码」做内层 SM4 加密（零知识）：

    - symmetric : 仅内层 SM4，密文直接落库（scheme='entry'）
    - gpg / sm2 : 内层 SM4 后再用 OrgKey 公钥（或服务端密钥）做一次非对称加密，
                  形成「外层非对称 + 内层对称」混合密文（scheme='legacy'）。
                  查看/修改时必须同时持有私钥（服务端）与条目密码（内层）才能还原明文。
    """
    algo = (req.algorithm or "symmetric").lower()
    if not req.entry_password:
        raise HTTPException(
            status_code=400,
            detail="无论采用哪种加密方式，新增密码都必须填写「解密密码」",
        )
    # 内层：条目密码 SM4-CBC（带 salt/iv，服务端不持久化密码本身）
    inner = entry_cipher.encrypt_entry(req.secret, req.entry_password)
    if algo == "symmetric":
        return {
            "algorithm": "symmetric",
            "scheme": "entry",
            "ciphertext": inner["ciphertext"],
            "entry_salt": inner["salt"],
            "entry_iv": inner["iv"],
            "orgkey_id": None,
        }
    if algo in ("gpg", "sm2"):
        inner_blob = json.dumps(inner, ensure_ascii=False)
        orgkey = _resolve_orgkey(db, user, req.orgkey_id, req.group_id)
        if orgkey is not None:
            try:
                ciphertext = manager.get_provider(algo).encrypt(inner_blob, orgkey.public_key)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"用 OrgKey 公钥加密失败：{e}") from e
            return {
                "algorithm": algo,
                "scheme": "legacy",
                "ciphertext": ciphertext,
                "entry_salt": inner["salt"],
                "entry_iv": inner["iv"],
                "orgkey_id": orgkey.id,
            }
        # 回退：服务端默认密钥（兼容 OrgKey 库为空的情况）
        return {
            "algorithm": algo,
            "scheme": "legacy",
            "ciphertext": manager.encrypt_secret(db, algo, inner_blob),
            "entry_salt": inner["salt"],
            "entry_iv": inner["iv"],
            "orgkey_id": None,
        }
    raise HTTPException(status_code=400, detail=f"不支持的加密方式: {algo}")


def _legacy_decrypt(db: Session, e: PasswordEntry) -> str:
    """解开 legacy 外层（GPG/SM2），返回内层原文。

    hybrid 条目下内层是 JSON 字符串（{salt,iv,ciphertext}）；旧式纯 legacy 下内层即明文。
    """
    if e.orgkey_id:
        k = db.query(OrgKey).filter_by(id=e.orgkey_id).first()
        if k and k.private_key:
            try:
                return manager.get_provider(e.algorithm).decrypt(e.ciphertext, k.private_key)
            except Exception as ex:
                raise HTTPException(
                    status_code=500,
                    detail=f"用 OrgKey 私钥解密失败：{ex}",
                ) from ex
        # 若 OrgKey 已不存在或无私钥，回退到服务端默认密钥
    return manager.decrypt_secret(db, e.algorithm, e.ciphertext)


def _decrypt_entry_secret(db: Session, e: PasswordEntry, entry_password: Optional[str]) -> str:
    """解密单条密码明文。

    - 无内层条目密码（旧式纯 legacy）：直接用服务端/GroKey 私钥解密返回；
    - 有内层条目密码（symmetric 或 hybrid gpg/sm2）：必须提供且正确的 entry_password 才能解开内层 SM4。
    """
    has_entry = bool(e.entry_salt) and bool(e.entry_iv)
    if not has_entry:
        # 旧版 legacy：纯 GPG/SM2，无需条目密码
        return _legacy_decrypt(db, e)
    if not entry_password:
        raise HTTPException(
            status_code=400,
            detail="该密码由「解密密码」保护，请提供 entry_password 才能查看",
        )
    try:
        if e.scheme == "entry":
            plaintext = entry_cipher.decrypt_entry(
                {"salt": e.entry_salt, "iv": e.entry_iv, "ciphertext": e.ciphertext},
                entry_password,
            )
        else:
            inner_blob = _legacy_decrypt(db, e)  # hybrid：外层 GPG/SM2 -> 内层 JSON
            inner = json.loads(inner_blob)
            plaintext = entry_cipher.decrypt_entry(inner, entry_password)
    except entry_cipher.WrongPasswordError:
        raise HTTPException(status_code=401, detail="解密密码错误，无法解密")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="密文格式损坏，无法解析内层数据")
    return plaintext


@router.get("")
def list_passwords(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    gids = get_user_group_ids(db, user)
    f = visibility_filter(PasswordEntry.group_id, user, gids)
    q = db.query(PasswordEntry).filter_by(deleted=False)
    if f is not None:
        q = q.filter(f)
    rows = q.order_by(PasswordEntry.updated_at.desc()).all()
    return [_serialize_meta(db, r) for r in rows]


@router.post("")
def create(
    req: CreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_group_access(db, user, req.group_id)

    fields = _encrypt_for_create(db, user, req)
    entry = PasswordEntry(
        title=(req.title or "").strip(),
        username=req.username,
        notes=req.notes,
        group_id=req.group_id,
        created_by=user.username,
        updated_by=user.username,
        **fields,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    db.add(
        History(
            password_id=entry.id,
            group_id=entry.group_id,
            action="create",
            title=entry.title,
            username=entry.username,
            algorithm=entry.algorithm,
            ciphertext=entry.ciphertext,
            notes=entry.notes,
            changed_by=user.username,
            comment=req.comment or "新增密码",
        )
    )
    db.commit()
    return {"id": entry.id, "message": "created"}


@router.get("/{pid}")
def get_one(
    pid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """无「解密密码」的旧式条目（纯 GPG/SM2 服务端密钥加密）可直接查看；
    受「解密密码」保护的条目请使用 POST /{pid}/unlock 并在请求体中传密码。"""
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)
    if bool(entry.entry_salt) and bool(entry.entry_iv):
        raise HTTPException(
            status_code=400,
            detail="该密码由「解密密码」保护，请使用 POST /api/passwords/{id}/unlock 并在请求体中传 entry_password",
        )
    secret = _decrypt_entry_secret(db, entry, None)
    return {**_serialize_meta(db, entry), "secret": secret}


@router.post("/{pid}/unlock")
def unlock(
    pid: int,
    req: UnlockRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """受「解密密码」保护的条目：用请求体（JSON）传 entry_password，解密后返回明文。
    密码只在请求体内传输，不会出现在 URL / 访问日志 / 浏览器历史中。"""
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)
    secret = _decrypt_entry_secret(db, entry, req.entry_password)
    return {**_serialize_meta(db, entry), "secret": secret}


@router.put("/{pid}")
def update(
    pid: int,
    req: UpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)

    changes: list[str] = []
    if req.title is not None and req.title != entry.title:
        entry.title = req.title
        changes.append("title")
    if req.username is not None and req.username != entry.username:
        entry.username = req.username
        changes.append("username")
    if req.notes is not None and req.notes != entry.notes:
        entry.notes = req.notes
        changes.append("notes")
    if req.orgkey_id is not None and req.orgkey_id != entry.orgkey_id:
        changes.append("orgkey_id")

    has_entry = bool(entry.entry_salt) and bool(entry.entry_iv)
    target_algo = (req.algorithm or entry.algorithm or "symmetric").lower()
    target_scheme = "entry" if target_algo == "symmetric" else "legacy"
    algo_changed = target_algo != entry.algorithm or (
        ("entry" if entry.algorithm == "symmetric" else "legacy") != target_scheme
    )

    # 旧式纯 legacy（无解密密码层）且目标仍为 legacy 且未提供新解密密码 -> 维持旧式（不引入条目密码层）
    preserve_noentry = (not has_entry) and target_algo in ("gpg", "sm2") and not (
        req.new_entry_password or req.entry_password
    )

    # ---- 读取当前明文 ----
    if preserve_noentry:
        current_secret = _legacy_decrypt(db, entry)
    else:
        if has_entry:
            if not req.entry_password:
                raise HTTPException(
                    status_code=400,
                    detail="修改受「解密密码」保护的密码必须提供 entry_password",
                )
            try:
                if entry.scheme == "entry":
                    current_secret = entry_cipher.decrypt_entry(
                        {"salt": entry.entry_salt, "iv": entry.entry_iv, "ciphertext": entry.ciphertext},
                        req.entry_password,
                    )
                else:
                    inner_blob = _legacy_decrypt(db, entry)
                    current_secret = entry_cipher.decrypt_entry(json.loads(inner_blob), req.entry_password)
            except entry_cipher.WrongPasswordError:
                raise HTTPException(status_code=401, detail="解密密码错误，无法修改")
        else:
            # 旧式 legacy 升级：无需密码即可读取，但写入时必须指定解密密码
            current_secret = _legacy_decrypt(db, entry)

    # 仅在明确提供了非空新明文时才替换；空串视为「保持不变」，
    # 避免编辑标题/备注时因前端不预填明文而误将密码清空。
    if req.secret not in (None, ""):
        new_secret = req.secret
        if req.secret != current_secret:
            changes.append("secret")
    else:
        new_secret = current_secret

    if target_algo not in ("symmetric", "gpg", "sm2"):
        raise HTTPException(status_code=400, detail=f"不支持的加密方式: {target_algo}")

    # ---- 维持旧式（纯 GPG/SM2，无解密密码层）----
    if preserve_noentry:
        if new_secret != current_secret or (req.orgkey_id is not None and req.orgkey_id != entry.orgkey_id):
            orgkey = _resolve_orgkey(db, user, req.orgkey_id, entry.group_id) if req.orgkey_id is not None else None
            if orgkey is not None:
                entry.ciphertext = manager.get_provider(target_algo).encrypt(new_secret, orgkey.public_key)
                entry.orgkey_id = orgkey.id
            else:
                entry.ciphertext = manager.encrypt_secret(db, target_algo, new_secret)
                entry.orgkey_id = None
            entry.entry_salt = ""
            entry.entry_iv = ""
        entry.algorithm = target_algo
        entry.scheme = "legacy"
    else:
        # ---- 新设计：始终带「解密密码」内层 ----
        enc_pw = req.new_entry_password or req.entry_password
        if not enc_pw:
            raise HTTPException(
                status_code=400,
                detail="必须提供解密密码（或新解密密码）才能保存",
            )
        inner = entry_cipher.encrypt_entry(new_secret, enc_pw)
        if target_scheme == "entry":
            entry.algorithm = "symmetric"
            entry.scheme = "entry"
            entry.ciphertext = inner["ciphertext"]
            entry.entry_salt = inner["salt"]
            entry.entry_iv = inner["iv"]
            entry.orgkey_id = None
        else:
            inner_blob = json.dumps(inner, ensure_ascii=False)
            orgkey = _resolve_orgkey(db, user, req.orgkey_id, entry.group_id)
            if orgkey is not None:
                try:
                    entry.ciphertext = manager.get_provider(target_algo).encrypt(inner_blob, orgkey.public_key)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"用 OrgKey 公钥加密失败：{e}") from e
                entry.orgkey_id = orgkey.id
            else:
                entry.ciphertext = manager.encrypt_secret(db, target_algo, inner_blob)
                entry.orgkey_id = None
            entry.algorithm = target_algo
            entry.scheme = "legacy"
            entry.entry_salt = inner["salt"]
            entry.entry_iv = inner["iv"]

    if (not preserve_noentry) and req.new_entry_password:
        changes.append("entry_password")
    if algo_changed:
        changes.append("algorithm")
    entry.updated_by = user.username
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()

    db.add(
        History(
            password_id=entry.id,
            group_id=entry.group_id,
            action="update",
            title=entry.title,
            username=entry.username,
            algorithm=entry.algorithm,
            ciphertext=entry.ciphertext,
            notes=entry.notes,
            changed_by=user.username,
            comment=req.comment or ("修改了 " + ",".join(changes) if changes else "无变更"),
        )
    )
    db.commit()
    return {"id": pid, "message": "updated", "changes": changes}


@router.delete("/{pid}")
def delete(
    pid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)
    entry.deleted = True
    entry.updated_by = user.username
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.add(
        History(
            password_id=pid,
            group_id=entry.group_id,
            action="delete",
            title=entry.title,
            username=entry.username,
            algorithm=entry.algorithm,
            ciphertext=entry.ciphertext,
            notes=entry.notes,
            changed_by=user.username,
            comment="删除密码",
        )
    )
    db.commit()
    return {"id": pid, "message": "deleted"}


def _build_export_rows(db: Session, entries: list, plaintext: bool, passwords: dict) -> tuple:
    """构造导出数据行。返回 (rows, skipped)。

    - plaintext=False（加密备份）：仅含密文与元数据，无需密码，可用于迁移 / 恢复。
    - plaintext=True：尝试用 passwords 中的解密密码还原明文；失败则该条 secret=None 并计入 skipped。
    """
    groups = {g.id: g.name for g in db.query(Group).all()}
    rows = []
    skipped = 0
    for e in entries:
        key_name = None
        if e.orgkey_id:
            k = db.query(OrgKey).filter_by(id=e.orgkey_id).first()
            if k:
                key_name = k.name
        has_entry = bool(e.entry_salt) and bool(e.entry_iv)
        row = {
            "id": e.id,
            "username": e.username,
            "algorithm": e.algorithm,
            "scheme": e.scheme,
            "group_id": e.group_id,
            "group_name": groups.get(e.group_id, "—"),
            "key_name": key_name,
            "notes": e.notes or "",
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        }
        if plaintext:
            pw = passwords.get(str(e.id)) or passwords.get(e.id)
            secret = None
            decrypt_error = False
            if not has_entry:
                # 旧式纯 legacy：服务端密钥可直接还原
                try:
                    secret = _legacy_decrypt(db, e)
                except Exception:
                    decrypt_error = True
                    skipped += 1
            else:
                try:
                    secret = _decrypt_entry_secret(db, e, pw)
                except Exception:
                    decrypt_error = True
                    skipped += 1
            row["secret"] = secret
            row["decrypt_error"] = decrypt_error
        else:
            # 加密备份：仅导出密文，不含明文
            row["ciphertext"] = e.ciphertext
            row["entry_salt"] = e.entry_salt or ""
            row["entry_iv"] = e.entry_iv or ""
            row["orgkey_id"] = e.orgkey_id
        rows.append(row)
    return rows, skipped


def _export_filename(fmt: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"密码导出_{ts}.{ 'csv' if fmt == 'csv' else 'json' }"


@router.post("/export")
def export_passwords(
    req: ExportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """批量导出所选密码。

    - plaintext=False：加密备份（含密文 + 元数据），无需密码，可用于迁移 / 恢复。
    - plaintext=True：明文导出，需通过 passwords 提供各条目的解密密码；解密失败者 secret 为 null。
    解密密码通过请求体（JSON）传输，不会出现在 URL 中。
    """
    fmt = (req.format or "json").lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(status_code=400, detail="不支持的导出格式")
    if not req.ids:
        raise HTTPException(status_code=400, detail="请至少选择一条密码")

    gids = get_user_group_ids(db, user)
    f = visibility_filter(PasswordEntry.group_id, user, gids)
    q = db.query(PasswordEntry).filter_by(deleted=False).filter(PasswordEntry.id.in_(req.ids))
    if f is not None:
        q = q.filter(f)
    entries = q.all()
    if not entries:
        raise HTTPException(status_code=404, detail="没有可导出的可见条目")

    rows, skipped = _build_export_rows(db, entries, req.plaintext, req.passwords or {})

    if fmt == "csv":
        buf = io.StringIO()
        fieldnames = [
            "id", "username", "algorithm", "group_name", "key_name",
            "secret", "notes", "updated_at",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({
                "id": r["id"],
                "username": r["username"],
                "algorithm": r["algorithm"],
                "group_name": r["group_name"],
                "key_name": r["key_name"] or "",
                "secret": r.get("secret") if r.get("secret") is not None else ("解密失败" if r.get("decrypt_error") else ""),
                "notes": r["notes"],
                "updated_at": r["updated_at"] or "",
            })
        content = buf.getvalue().encode("utf-8-sig")
        media_type = "text/csv; charset=utf-8"
    else:
        payload = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "plaintext": req.plaintext,
            "count": len(rows),
            "skipped": skipped,
            "entries": rows,
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        media_type = "application/json; charset=utf-8"

    fname = _export_filename(fmt)
    ascii_name = f"password_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ 'csv' if fmt == 'csv' else 'json' }"
    disposition = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(fname)}'
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": disposition})
