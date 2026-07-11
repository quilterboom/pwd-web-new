from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import (
    ensure_group_access,
    get_current_user,
    get_user_group_ids,
    require_admin,
)
from ..crypto import manager
from ..db import get_db
from ..models import History, KeyRecord, OrgKey, User

router = APIRouter(tags=["keys"])


# ============================================================
# 已有：服务端密钥状态（用于密码/文件 legacy 方案的就绪检查）
# ============================================================
@router.get("/api/keys/status")
def keys_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    present = {r.algorithm: True for r in db.query(KeyRecord).all()}
    return {algo: present.get(algo, False) for algo in manager.SUPPORTED}


# ============================================================
# 新增：组织密钥库（按组织维度的多密钥管理）
# ============================================================
orgkeys_router = APIRouter(
    prefix="/api/orgkeys",
    tags=["orgkeys"],
    dependencies=[Depends(get_current_user)],
)


class GenerateRequest(BaseModel):
    name: str
    algorithm: str  # 'gpg' | 'sm2'
    group_id: int
    comment: str = ""


class ImportRequest(BaseModel):
    name: str
    algorithm: str  # 'gpg' | 'sm2'
    group_id: int
    public_key: str = ""        # armored PEM（GPG）或 hex（SM2）
    private_key: str = ""       # armored PEM（GPG）或 hex（SM2）
    private_passphrase: str = ""  # GPG：受口令保护的私钥需要该口令；留空表示私钥未受保护
    comment: str = ""


def _fingerprint(algorithm: str, public_key: str) -> str:
    """为密钥计算可读指纹——GPG 用 PGPKey 的真实指纹，SM2 取公钥前 16 hex + 散列前 8 hex。"""
    try:
        if algorithm == "gpg":
            import sys, types
            if "imghdr" not in sys.modules:
                _imghdr = types.ModuleType("imghdr")
                _imghdr.what = lambda file, h=None: None
                sys.modules["imghdr"] = _imghdr
            import pgpy
            pub = pgpy.PGPKey.from_blob(public_key)[0]
            return str(pub.fingerprint).replace(" ", "").upper()
    except Exception:
        pass
    pub = (public_key or "").strip()
    if len(pub) >= 16:
        return pub[:8] + "…" + pub[-8:]
    return pub[:16] or "?"


def _validate_keys(algorithm: str, public_key: str, private_key: str = "", private_passphrase: str = "") -> None:
    """校验用户上传/粘贴的密钥格式是否可解析。失败抛 400。

    对于 GPG 受口令保护的私钥，调用方必须同时传入 ``private_passphrase``；我们会用该口令
    对私钥进行一次「decrypt-roundtrip」校验，确保口令正确可用。
    """
    if algorithm not in ("gpg", "sm2"):
        raise HTTPException(status_code=400, detail=f"不支持的算法: {algorithm}")
    if not public_key:
        raise HTTPException(status_code=400, detail="缺少公钥内容")
    provider = manager.get_provider(algorithm)
    try:
        provider.encrypt("密码管理-test", public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="公钥格式无效，请检查公钥内容") from None
    if private_key:
        try:
            provider.decrypt(
                provider.encrypt("密码管理-test-roundtrip", public_key),
                private_key,
                passphrase=private_passphrase or None,
            )
        except ValueError as e:
            # 受口令保护 / 口令为空等「明确错误」，直接透传清晰文案，避免被笼统的“不匹配”掩盖
            raise HTTPException(status_code=400, detail=str(e)) from e
        except Exception:
            raise HTTPException(status_code=400, detail="私钥与公钥不匹配或无效") from None


def _export_filename(rec: OrgKey, kind: str) -> str:
    """生成 ASCII 安全的下载头文件名（防 HTTP header latin-1 编码失败）。"""
    safe = "".join(
        c if c.isascii() and (c.isalnum() or c in ".-_") else "_"
        for c in (rec.name or "key")
    )
    if rec.algorithm == "gpg":
        ext = ".asc"
    else:
        ext = ".key"
    suffix = "_pub" if kind == "public" else "_priv"
    return f"{safe}{suffix}{ext}"


def _pretty_filename(rec: OrgKey, kind: str) -> str:
    """人类可读文件名（保留原始中文名，先进浏览器优先用此字段）。"""
    suffix = "_pub" if kind == "public" else "_priv"
    ext = ".asc" if rec.algorithm == "gpg" else ".key"
    pretty = (rec.name or "key").replace("\r", " ").replace("\n", " ")
    return f"{pretty}{suffix}{ext}"


@orgkeys_router.get("")
def list_orgkeys(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    group_id: int | None = Query(default=None),
    algorithm: str | None = Query(default=None),
    page: int = None,
    page_size: int = None,
    q: Optional[str] = None,
):
    """列出当前用户所属组织（或指定组织）下的密钥；可按 algorithm / 分组 / 关键字过滤。

    - 不传 page_size：返回完整扁平数组（兼容旧调用 / 其它内部页面）。
    - 传 page_size：返回分页信封 {"items", "total", "page", "page_size"}（密钥库页走此路径）。
    - q：按「密钥名 / 创建人」模糊搜索（后台执行）。
    """
    qry = db.query(OrgKey)
    visible = get_user_group_ids(db, user)
    if not visible:
        # 无可见分组：未指定分页返回空数组，指定分页返回空信封（保持契约一致）
        if page_size is None:
            return []
        return {"items": [], "total": 0, "page": 1, "page_size": page_size}
    qry = qry.filter(OrgKey.group_id.in_(visible))
    if group_id is not None:
        qry = qry.filter(OrgKey.group_id == group_id)
    if algorithm is not None:
        qry = qry.filter(OrgKey.algorithm == algorithm)
    rows = qry.order_by(OrgKey.group_id.asc(), OrgKey.created_at.desc()).all()
    if q:
        ql = q.strip().lower()
        rows = [r for r in rows if ql in (r.name or "").lower() or ql in (r.created_by or "").lower()]
    total = len(rows)
    # 未指定分页 → 兼容旧调用：返回完整扁平数组
    if page_size is None:
        return [_orgkey_out(r) for r in rows]
    # 指定分页 → 返回信封
    page = page or 1
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 20
    if page_size > 5000:
        page_size = 5000
    total_pages = (total + page_size - 1) // page_size or 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    page_rows = rows[start:start + page_size]
    items = [_orgkey_out(r) for r in page_rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def _orgkey_out(r: OrgKey) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "algorithm": r.algorithm,
        "group_id": r.group_id,
        "fingerprint": r.fingerprint,
        "has_private": r.has_private,
        "private_protected": bool(r.private_protected),
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


@orgkeys_router.post("/generate")
def generate_orgkey(req: GenerateRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if req.algorithm not in manager.SUPPORTED:
        raise HTTPException(status_code=400, detail=f"不支持的算法: {req.algorithm}")
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="请输入密钥名称")
    ensure_group_access(db, user, req.group_id)

    pub, priv = manager.get_provider(req.algorithm).generate_keypair()
    fp = _fingerprint(req.algorithm, pub)
    rec = OrgKey(
        group_id=req.group_id,
        name=req.name.strip(),
        algorithm=req.algorithm,
        public_key=pub,
        private_key=priv,
        fingerprint=fp,
        has_private=True,
        private_protected=False,  # 服务端自生成密钥不带口令
        is_protected=False,        # 老库兼容性
        created_by=user.username,
    )
    db.add(rec)
    db.commit()
    return {"id": rec.id, "fingerprint": fp, "algorithm": rec.algorithm, "has_private": rec.has_private, "private_protected": False}


@orgkeys_router.post("/import")
def import_orgkey(req: ImportRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="请输入密钥名称")
    ensure_group_access(db, user, req.group_id)
    has_priv = bool(req.private_key.strip())
    pp = (req.private_passphrase or "").strip()
    # 即使没填 passphrase，也要先校验一遍（pgpy 会自动检测并报清晰错误）
    _validate_keys(req.algorithm, req.public_key, req.private_key, pp)
    fp = _fingerprint(req.algorithm, req.public_key)
    rec = OrgKey(
        group_id=req.group_id,
        name=req.name.strip(),
        algorithm=req.algorithm,
        public_key=req.public_key.strip(),
        private_key=req.private_key.strip() if has_priv else None,
        fingerprint=fp,
        has_private=has_priv,
        private_protected=bool(pp),
        private_passphrase=pp,
        # 老库的 legacy ``is_protected`` 列无默认值（pgen 未设置 → NOT NULL 失败），
        # 这里显式给定一个与 ``private_protected`` 一致的值，保证各版本库都能写入。
        is_protected=bool(pp),
        created_by=user.username,
    )
    db.add(rec)
    db.commit()
    return {
        "id": rec.id,
        "fingerprint": fp,
        "has_private": has_priv,
        "private_protected": rec.private_protected,
    }


@orgkeys_router.get("/{kid}/export")
def export_orgkey(
    kid: int,
    kind: str = Query(default="public", pattern="^(public|private)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """导出公钥或私钥为文本/二进制附件下载。"""
    rec = db.query(OrgKey).filter_by(id=kid).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="密钥不存在")
    ensure_group_access(db, user, rec.group_id)
    if kind == "public":
        body = rec.public_key
        if rec.algorithm == "sm2":
            body_bytes = body.encode("utf-8")
            media = "text/plain"
        else:
            body_bytes = body.encode("utf-8")
            media = "application/pgp-keys"
        fname = _export_filename(rec, "public")
    else:  # private
        if not rec.private_key:
            raise HTTPException(status_code=404, detail="该密钥未持有私钥")
        body = rec.private_key
        body_bytes = body.encode("utf-8")
        media = "application/pgp-keys" if rec.algorithm == "gpg" else "text/plain"
        fname = _export_filename(rec, "private")

    from urllib.parse import quote
    ascii_fname = _export_filename(rec, kind)
    pretty_fname = _pretty_filename(rec, kind)
    return Response(
        content=body_bytes,
        media_type=media,
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_fname}\"; "
                f"filename*=UTF-8''{quote(pretty_fname)}"
            )
        },
    )


@orgkeys_router.delete("/{kid}")
def delete_orgkey(kid: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rec = db.query(OrgKey).filter_by(id=kid).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="密钥不存在")
    ensure_group_access(db, user, rec.group_id)
    name = rec.name
    algo = rec.algorithm
    gid = rec.group_id
    db.delete(rec)
    db.commit()
    # 与删除密码一致：生成一条删除记录供管理员在「审计日志」中查看
    db.add(
        History(
            password_id=None,
            group_id=gid,
            action="delete",
            title=name,
            username=None,
            algorithm=algo,
            ciphertext=None,
            notes=None,
            changed_by=user.username,
            comment=f"删除密钥（名称：{name}）",
        )
    )
    db.commit()
    return {"ok": True}
