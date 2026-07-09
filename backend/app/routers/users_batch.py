"""批量新增用户：Excel / CSV 模板下载 + 解析上传 + 部分失败回执。

设计目标
=========
* 管理员可先下载模板（xlsx 或 csv），照表头填写后上传；
* 支持两种文件格式：``.xlsx``（用 openpyxl 生成与解析）和 ``.csv``（用 csv 模块；
  备选方案，只要环境里 xlrd 没装也能跑）。
* 上传后逐行解析、逐行创建；某行失败不影响其它行。响应里逐行列出「成功 / 失败原因」。
* 单密码字段强度不做强制（管理员场景），但必须非空。
"""
from __future__ import annotations

import csv
import io
from typing import Iterable, List, Tuple

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import require_admin
from ..db import get_db
from ..models import Group, User, user_groups
from ..security import derive_password_verifier, hash_password
from .admin import _link_user_group, _seed_login_material

router = APIRouter(prefix="/api/admin/users", tags=["admin-users-batch"])


# ────────────────────── 模板（xlsx / csv 两种） ──────────────────────

# Excel 模板表头（中英结合方便阅读，但解析时按中文字段识别）
TEMPLATE_HEADERS = ["用户名", "密码", "是否管理员", "所属分组"]


def _build_template_rows() -> List[List[str]]:
    """生成示例行：前 2 行为示例 + 表头说明，最后 1 行为管理员示例。"""
    return [
        # 下面是示例，可保留也可以全部删除后整列上传
        ["alice", "Alice@2026", "否", "研发部,测试组"],   # 多分组用半角逗号分隔
        ["bob", "BobSecret!9", "否", "研发部"],
        ["carol", "Carol#Admin1", "是", ""],            # 管理员可不绑定分组
    ]


def _xlsx_bytes(rows: List[List[str]], sheet_name: str = "用户批量导入模板") -> bytes:
    """用 openpyxl 渲染 xlsx 到 bytes（无需保存到磁盘）。"""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name

    bold = Font(bold=True)
    head_fill = PatternFill(start_color="FFEAF2FF", end_color="FFEAF2FF", fill_type="solid")
    center = Alignment(horizontal="center", vertical="center")

    # 第 1 行放使用说明
    ws.cell(row=1, column=1, value="使用说明").font = Font(bold=True, color="FF2563EB")
    instructions = [
        "1) 第 1 行为使用说明，解析时会忽略；请勿在下方插入空行。",
        "2) 第 2 行为表头，「所属分组」支持多个，用半角逗号分隔；留空表示不绑定任何分组。",
        "3) 第 3 行起是示例数据，仅作演示；管理员上传前请先清空示例行或保留作为格式参考。",
        "4) 「是否管理员」请填：是 / 否（不区分大小写）。其它值按「否」处理。",
        "5) 用户名重复、密码为空都会导致该行失败，其它行不受影响；",
        "   上传完成后会返回包含逐行结果的报告。",
    ]
    for i, line in enumerate(instructions, start=2):
        ws.cell(row=i, column=1, value=line)

    # 留一行空行
    note_end = 1 + len(instructions)
    ws.cell(row=note_end + 2, column=1, value="下方为模板数据（请在此区域内填写）：").font = Font(bold=True)

    body_start = note_end + 4  # 标题行

    # 表头
    for col_idx, header in enumerate(TEMPLATE_HEADERS, start=1):
        c = ws.cell(row=body_start, column=col_idx, value=header)
        c.font = bold
        c.fill = head_fill
        c.alignment = center

    # 主体行（示例）
    for r, row in enumerate(_build_template_rows(), start=body_start + 1):
        for c_idx, val in enumerate(row, start=1):
            cell = ws.cell(row=r, column=c_idx, value=val)
            cell.alignment = Alignment(vertical="center")

    # 列宽
    for col_idx, header in enumerate(TEMPLATE_HEADERS, start=1):
        width = max(14, len(str(header)) * 2 + 4)
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    # 保存到内存
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _csv_bytes() -> bytes:
    """CSV 形式的备选模板（无 excel 环境也能下载）。"""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["# 用户批量导入模板（# 号开头的行作为说明，解析时会被忽略）"])
    writer.writerow(["# 第 3 行起为示例数据，上传前可删除。"])
    writer.writerow(TEMPLATE_HEADERS)
    for r in _build_template_rows():
        writer.writerow(r)
    # 加 UTF-8 BOM 让 Excel 直接打开不乱码
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


@router.get("/template")
def download_template(
    fmt: str = "xlsx",
    _: User = Depends(require_admin),
):
    """下载批量导入用户的模板。

    - ``fmt=xlsx``（默认）：返回 .xlsx
    - ``fmt=csv``         ：返回 .csv（含 UTF-8 BOM，Excel 打开不乱码）
    """
    fmt = (fmt or "xlsx").lower()
    if fmt == "xlsx":
        data = _xlsx_bytes([])
        filename = "用户批量导入模板.xlsx"
        media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "csv":
        data = _csv_bytes()
        filename = "用户批量导入模板.csv"
        media = "text/csv; charset=utf-8"
    else:
        raise HTTPException(status_code=400, detail="fmt 仅支持 xlsx / csv")

    # 双字段 Content-Disposition：ASCII 兼容 + UTF-8 兼容
    from urllib.parse import quote
    quoted = quote(filename)
    headers = {
        "Content-Disposition": (
            f"attachment; filename=\"import_template.{fmt}\"; filename*=UTF-8''{quoted}"
        )
    }
    return StreamingResponse(io.BytesIO(data), media_type=media, headers=headers)


# ────────────────────── 上传解析 ──────────────────────


def _norm_row(row: dict) -> Tuple[str, str, bool, List[str]]:
    """把一行数据归一化成 (username, password, is_admin, group_names)。

    输入 ``row`` 的 key 是「角色名」（username / password / is_admin / group），由解析层
    （_read_xlsx / _read_csv）已经从原始中文表头映射好；这里只做取值与清洗，不涉及表头。
    """
    username = (row.get("username") or "").strip()
    password = (row.get("password") or "").strip()
    admin_raw = (row.get("is_admin") or "").strip().lower()
    is_admin = admin_raw in ("是", "yes", "y", "true", "1", "管理员")
    group_names_raw = (row.get("group") or "").strip()
    group_names = [g.strip() for g in group_names_raw.split(",") if g.strip()]
    return username, password, is_admin, group_names


def _resolve_groups(db: Session, names: List[str]) -> Tuple[List[int], List[str]]:
    """把分组名列表解析为 id 列表。不存在 / 重名的名字会被收集起来返回给前端展示。"""
    ids: List[int] = []
    missing: List[str] = []
    if not names:
        return ids, missing
    for n in names:
        g = db.query(Group).filter_by(name=n).first()
        if g:
            ids.append(g.id)
        else:
            missing.append(n)
    return ids, missing


def _read_xlsx(content: bytes, skip_note_rows: int = 7) -> List[dict]:
    """从 xlsx bytes 提取行；返回 dict 列表（key 是中文字段）。"""
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    ws = wb.active
    rows_iter = ws.iter_rows(values_only=True)
    headers = None
    out: List[dict] = []
    for r in rows_iter:
        row = [c for c in r if c is not None]
        if not row:
            continue
        first = str(row[0]).strip() if row else ""
        # 跳过说明行（# 开头 / 「使用说明」/「下方为模板数据…」）
        if first.startswith("#") or first.startswith("使用说明") or first.startswith("下方为"):
            continue
        if headers is None:
            # 把表头键统一为归一化字段标识
            raw_headers = [str(x).strip() for x in row]
            if "用户名" not in raw_headers:
                # 表头未识别，跳过该行继续找
                continue
            headers = {
                "username": "用户名",
                "password": "密码",
                "is_admin": "是否管理员",
                "group": "所属分组",
            }
            continue
        # 普通数据行：用 raw_headers index 对齐
        # 重新取一次完整行（包括 None），以便按列名索引
        full = list(r)
        # 同一列号取单元格
        cells = {}
        for key, header_name in headers.items():
            try:
                col_idx = raw_headers.index(header_name)
            except ValueError:
                continue
            if col_idx < len(full):
                cells[key] = "" if full[col_idx] is None else str(full[col_idx])
            else:
                cells[key] = ""
        out.append(cells)
    wb.close()
    return out


def _read_csv(content: bytes) -> List[dict]:
    """从 csv bytes 提取行。"""
    text = content.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    headers_map = {
        "username": "用户名",
        "password": "密码",
        "is_admin": "是否管理员",
        "group": "所属分组",
    }
    headers = None
    out: List[dict] = []
    for row in reader:
        if not row or all((c or "").strip() == "" for c in row):
            continue
        first = (row[0] or "").strip()
        if first.startswith("#"):
            continue
        if headers is None:
            if "用户名" not in row:
                continue
            headers = list(row)
            continue
        cells = {}
        for key, header_name in headers_map.items():
            try:
                col_idx = headers.index(header_name)
            except ValueError:
                continue
            cells[key] = (row[col_idx].strip() if col_idx < len(row) else "")
        out.append(cells)
    return out


class BatchResultRow(BaseModel):
    row: int
    username: str
    status: str  # "created" | "skipped" | "error"
    message: str = ""


class BatchResponse(BaseModel):
    total: int
    created: int
    skipped: int
    errored: int
    rows: List[BatchResultRow]


@router.post("/batch", response_model=BatchResponse)
async def batch_import_users(
    file: UploadFile = File(...),
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """批量导入用户：上传 .xlsx / .csv 文件，逐行创建用户并报告每行的结果。"""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="文件为空")

    fname = (file.filename or "").lower()
    if fname.endswith(".xlsx"):
        try:
            data_rows = _read_xlsx(raw)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"无法解析 xlsx：{e}")
    elif fname.endswith(".csv"):
        try:
            data_rows = _read_csv(raw)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"无法解析 csv：{e}")
    else:
        raise HTTPException(status_code=400, detail="仅支持 .xlsx 或 .csv 文件")

    if not data_rows:
        raise HTTPException(status_code=400, detail="未找到可导入的数据行；请检查表头是否为「用户名 / 密码 / 是否管理员 / 所属分组」")

    # 调试：打印出读取到的每一行（仅诊断时可见）
    print(f"[batch_import] got {len(data_rows)} data rows:", data_rows[:3], "...", file=__import__("sys").stderr)

    headers_map = {
        "username": "用户名",
        "password": "密码",
        "is_admin": "是否管理员",
        "group": "所属分组",
    }

    results: List[BatchResultRow] = []
    created = skipped = errored = 0

    for idx, raw_row in enumerate(data_rows, start=1):
        username, password, is_admin, group_names = _norm_row(raw_row)
        if not username and not password:
            # 空行：跳过，计入 skipped（不报错，避免模板示例行报错）
            results.append(BatchResultRow(row=idx, username="", status="skipped", message="空行已跳过"))
            skipped += 1
            continue

        if not username:
            results.append(BatchResultRow(row=idx, username="", status="error", message="用户名为空"))
            errored += 1
            continue
        if not password:
            results.append(BatchResultRow(row=idx, username=username, status="error", message="密码为空"))
            errored += 1
            continue

        if db.query(User).filter_by(username=username).first():
            results.append(BatchResultRow(row=idx, username=username, status="error", message="用户名已存在"))
            errored += 1
            continue

        # 分组解析
        group_ids, missing = _resolve_groups(db, group_names)
        if missing:
            # 全部分组都缺失时视为错误；否则仅警告
            if not group_ids:
                results.append(BatchResultRow(row=idx, username=username, status="error",
                                               message=f"分组 [{', '.join(missing)}] 不存在"))
                errored += 1
                continue
            else:
                warn_msg = f"已忽略不存在的分组：{', '.join(missing)}"
            warn = warn_msg  # 准备后面追加到 ok 信息里
        else:
            warn = ""

        # 创建用户 + SCRAM 凭据
        user = User(
            username=username,
            hashed_password=hash_password(password),
            is_admin=is_admin,
        )
        _seed_login_material(user, password)
        db.add(user)
        try:
            db.flush()
        except Exception as e:
            db.rollback()
            results.append(BatchResultRow(row=idx, username=username, status="error", message=f"数据库写入失败：{e}"))
            errored += 1
            continue

        for gid in group_ids:
            _link_user_group(db, user.id, gid)
        db.commit()
        created += 1
        msg = "已创建" + (f"（{warn}）" if warn else "")
        results.append(BatchResultRow(row=idx, username=username, status="created", message=msg))

    return BatchResponse(
        total=len(data_rows),
        created=created,
        skipped=skipped,
        errored=errored,
        rows=results,
    )
