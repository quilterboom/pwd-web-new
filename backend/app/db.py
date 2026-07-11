from sqlalchemy import create_engine, inspect, text, event
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import DATABASE_URL

# timeout: sqlite3 _busy 等待(秒)，配合下方 PRAGMA busy_timeout 双保险
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 30})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# 并发加固：开启 WAL（读写互不阻塞、写不阻塞读）+ busy_timeout 自动重试，
# 避免多人同时写入时出现 "database is locked"。WAL 模式写入后会生成
# <db>-wal / <db>-shm 两个伴随文件，须与 .db 一同保留（已在 /app/data 卷内）。
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, conn_record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=30000")
    cur.close()
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    # 导入模型以确保表被注册到 Base.metadata
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_columns()


def _migrate_columns():
    """对已在运行的旧库做增量加列，避免离线服务器已有数据丢失。

    通用实现：扫描所有模型列，若某张表缺少某列，则用 ALTER TABLE ADD COLUMN 补上
    （自动带上 SQLite 兼容的默认值）。只新增、绝不删除或重命名，保证向后兼容，
    并且新增的列无需手工维护清单（避免漏列导致查询 500）。
    """
    from . import models  # noqa: F401  (确保模型已注册到 Base.metadata)
    from sqlalchemy import Boolean, Integer, String, Text, DateTime, LargeBinary

    insp = inspect(engine)
    existing = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}

    def column_decl(col):
        t = col.type
        if isinstance(t, Boolean):
            decl = "INTEGER"
        elif isinstance(t, String):
            decl = f"VARCHAR({t.length or 255})"
        elif isinstance(t, Text):
            decl = "TEXT"
        elif isinstance(t, DateTime):
            decl = "TIMESTAMP"
        elif isinstance(t, LargeBinary):
            decl = "BLOB"
        elif isinstance(t, Integer):
            decl = "INTEGER"
        else:
            decl = "TEXT"

        # 模型上的标量默认值（如 default=False / default="legacy"）
        default_arg = None
        d = col.default
        if d is not None and getattr(d, "is_scalar", False):
            default_arg = d.arg

        if default_arg is not None:
            if isinstance(default_arg, bool):
                decl += f" DEFAULT {1 if default_arg else 0}"
            elif isinstance(default_arg, (int, float)):
                decl += f" DEFAULT {default_arg}"
            else:
                decl += f" DEFAULT '{str(default_arg).replace(chr(39), chr(39) * 2)}'"
        elif not col.nullable:
            # NOT NULL 但没有模型默认值：给类型安全的兜底默认值，保证旧行可填充
            if isinstance(t, (Boolean, Integer)):
                decl += " DEFAULT 0"
            else:
                decl += " DEFAULT ''"

        if not col.nullable:
            decl += " NOT NULL"
        return decl

    with engine.begin() as conn:
        for table_name, table in Base.metadata.tables.items():
            cols = existing.get(table_name)
            if cols is None:
                # 整张表缺失交给 create_all 创建
                continue
            for col in table.columns:
                if col.name in cols:
                    continue
                try:
                    conn.execute(
                        text(f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {column_decl(col)}')
                    )
                except Exception as e:
                    # 兼容个别 SQLite 版本对 ADD COLUMN 默认值 / NOT NULL 的限制
                    # （最坏情况只跳过这一列，不影响其他列）
                    print(f"[migrate] skip {table_name}.{col.name}: {e}")
