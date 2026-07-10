// 通用展示工具：转义、时间格式化、算法徽章、分组名解析、历史字段中文化。

export function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
  }[c]))
}

export function fmtTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString('zh-CN', { hour12: false })
}

// 返回 { cls, label } 供 <span class="badge ..."> 渲染
export function algoBadge(a) {
  if (a === 'symmetric') return { cls: 'entry', label: '🔑 对称加密' }
  const label = a === 'sm2' ? 'SM2' : 'GPG'
  return { cls: a, label }
}

export function algoText(a) {
  if (a === 'symmetric') return '对称加密'
  if (a === 'sm2') return 'SM2'
  return 'GPG'
}

export function groupName(groups, id) {
  const g = groups.find((x) => x.id === id)
  return g ? g.name : '—'
}

const HISTORY_FIELD_LABELS = {
  title: '标题',
  username: '账号',
  notes: '备注',
  secret: '密码明文',
  entry_password: '解密密码',
  algorithm: '加密方式',
  orgkey_id: '加密密钥',
}
export const HISTORY_ACTION_LABELS = { create: '新增', update: '修改', delete: '删除', export: '导出' }

export function humanizeComment(c) {
  if (!c) return c
  return c.replace(/(修改了)\s+([^\s,.，。；;]+(?:[\s,，；;][^\s,.，。；;]+)*)/g, (_, verb, list) => {
    const parts = list.split(/[\s,，;；]+/).filter(Boolean)
    const translated = parts.map((p) => HISTORY_FIELD_LABELS[p] || p).join('，')
    return verb + ' ' + translated
  })
}
