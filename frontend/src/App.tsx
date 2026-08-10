import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Command,
  Download,
  Ellipsis,
  Eye,
  KeyRound,
  Link2,
  LockKeyhole,
  LogOut,
  Pencil,
  Plus,
  ScanLine,
  Search,
  Settings,
  Trash2,
  X,
} from "lucide-react";
import * as api from "./api";
import { ApiError } from "./api";
import { QrPasteZone } from "./QrPasteZone";
import { QrScanner } from "./QrScanner";
import type {
  Algorithm,
  EntryPayload,
  ExportEntry,
  ExportFile,
  ParsedOtpAuth,
  TotpEntry,
} from "./types";

interface Draft {
  issuer: string;
  account: string;
  label: string;
  secret: string;
  algorithm: Algorithm;
  digits: "6" | "8";
  period: string;
  uri: string;
}

type NoticeKind = "success" | "error" | "info";

interface AppNotice {
  id: number;
  message: string;
  kind: NoticeKind;
}

const emptyDraft = (): Draft => ({
  issuer: "",
  account: "",
  label: "",
  secret: "",
  algorithm: "SHA1",
  digits: "6",
  period: "30",
  uri: "",
});

function parseOtpAuthUri(value: string): ParsedOtpAuth | null {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") return null;
    const rawLabel = decodeURIComponent(url.pathname.replace(/^\//, ""));
    const separator = rawLabel.indexOf(":");
    const pathIssuer = separator >= 0 ? rawLabel.slice(0, separator) : "";
    const account = separator >= 0 ? rawLabel.slice(separator + 1) : rawLabel;
    const issuer = url.searchParams.get("issuer")?.trim() || pathIssuer.trim();
    const secret = url.searchParams.get("secret")?.replace(/\s+/g, "").replace(/=+$/, "").toUpperCase();
    const algorithm = (url.searchParams.get("algorithm") || "SHA1").toUpperCase();
    const digits = Number(url.searchParams.get("digits") || "6");
    const period = Number(url.searchParams.get("period") || "30");
    if (!secret || !account || !["SHA1", "SHA256", "SHA512"].includes(algorithm)) return null;
    if ((digits !== 6 && digits !== 8) || !Number.isInteger(period) || period < 1 || period > 86400) return null;
    return {
      issuer,
      account,
      label: issuer || account,
      secret,
      algorithm: algorithm as Algorithm,
      digits: digits as 6 | 8,
      period,
    };
  } catch {
    return null;
  }
}

function applyParsedUri(draft: Draft, parsed: ParsedOtpAuth): Draft {
  return {
    ...draft,
    issuer: parsed.issuer,
    account: parsed.account,
    label: parsed.label,
    secret: parsed.secret,
    algorithm: parsed.algorithm,
    digits: String(parsed.digits) as "6" | "8",
    period: String(parsed.period),
  };
}

function formatCode(code: string, digits: number) {
  if (digits === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

function remainingSeconds(entry: TotpEntry, now: number) {
  return Math.max(0, Math.ceil((entry.expiresAt - now) / 1000));
}

interface SegmentedProps<T extends string> {
  label: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
}

function Segmented<T extends string>({ label, value, options, onChange }: SegmentedProps<T>) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={option.value === value ? "is-active" : ""}
          aria-pressed={option.value === value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function friendlyError(error: unknown) {
  if (error instanceof ApiError) {
    const messages: Record<string, string> = {
      csrf_check_failed: "请求校验失败，请刷新页面后重试。",
      invalid_credentials: "密码错误。",
      rate_limited: "登录尝试次数过多，请稍后再试。",
      authentication_required: "请先登录。",
      session_expired: "登录已过期，请重新登录。",
      invalid_secret: "TOTP Secret 不是有效的 Base32。",
      missing_secret: "请输入 TOTP Secret。",
      invalid_otpauth_uri: "otpauth URI 无效。",
      invalid_entry: "条目设置无效。",
      empty_import: "导入文件中没有条目。",
      import_too_large: "一次最多导入 500 个条目。",
      unsupported_export_version: "不支持此导出文件版本。",
      not_found: "条目不存在。",
      internal_error: "服务器发生错误，请稍后重试。",
    };
    return messages[error.code] ?? "请求失败，请重试。";
  }
  if (error instanceof Error) return error.message;
  return "发生了一些问题，请重试。";
}

function useTotpStream(active: boolean, onEntries: (entries: TotpEntry[]) => void) {
  useEffect(() => {
    if (!active) return undefined;
    const source = new EventSource("/api/totp/stream");
    source.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as TotpEntry[] | { entries?: TotpEntry[] };
        onEntries(Array.isArray(payload) ? payload : payload.entries ?? []);
      } catch {
        // Ignore a malformed event; the next full snapshot will recover state.
      }
    };
    return () => source.close();
  }, [active, onEntries]);
}

function LoginScreen({ onLogin }: { onLogin: (password: string) => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await onLogin(password);
    } catch (loginError) {
      setError(friendlyError(loginError));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="login-lockup">
          <img className="brand-mark" src="/totem.svg" alt="" aria-hidden="true" />
          <h1>Totem</h1>
          <p>自托管 TOTP 验证器</p>
        </div>
        <form onSubmit={submit} className="login-form">
          <label htmlFor="admin-password">管理员密码</label>
          <input
            id="admin-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoFocus
            required
          />
          {error && <p className="form-error" role="alert">{error}</p>}
          <button className="primary-button full-width" type="submit" disabled={busy}>
            <LockKeyhole size={14} strokeWidth={2} aria-hidden="true" />
            {busy ? "验证中…" : "解锁 Totem"}
          </button>
        </form>
      </section>
    </main>
  );
}

interface EntryDialogProps {
  entry?: TotpEntry;
  onClose: () => void;
  onSave: (payload: EntryPayload) => Promise<void>;
}

function EntryDialog({ entry, onClose, onSave }: EntryDialogProps) {
  const [draft, setDraft] = useState<Draft>(() =>
    entry
      ? {
          issuer: entry.issuer,
          account: entry.account,
          label: entry.label,
          secret: "",
          algorithm: entry.algorithm,
          digits: String(entry.digits) as "6" | "8",
          period: String(entry.period),
          uri: "",
        }
      : emptyDraft(),
  );
  const [showSecret, setShowSecret] = useState(false);
  const [showScanner, setShowScanner] = useState(false);
  const [uriHint, setUriHint] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const setField = <K extends keyof Draft>(field: K, value: Draft[K]) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };

  const handleUri = (value: string) => {
    setField("uri", value);
    if (!value.trim()) {
      setUriHint("");
      return;
    }
    const parsed = parseOtpAuthUri(value);
    if (parsed) {
      setDraft((current) => applyParsedUri(current, parsed));
      setUriHint("URI 已解析，请检查下方字段后保存。");
    } else {
      setUriHint("粘贴有效的 otpauth://totp URI，表单会自动填充。");
    }
  };

  const handleScan = useCallback((value: string) => {
    const parsed = parseOtpAuthUri(value);
    if (!parsed) return false;
    setDraft((current) => applyParsedUri({ ...current, uri: value }, parsed));
    setUriHint("二维码已解析，请检查下方字段后保存。");
    setShowScanner(false);
    return true;
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    const period = Number(draft.period);
    if (!draft.account.trim()) {
      setError("账户不能为空。");
      return;
    }
    if (!entry && !draft.secret.trim()) {
      setError("Secret 不能为空。");
      return;
    }
    if (!Number.isInteger(period) || period < 1 || period > 86400) {
      setError("周期必须在 1 到 86400 秒之间。");
      return;
    }
    setBusy(true);
    try {
      const payload: EntryPayload = {
        issuer: draft.issuer.trim(),
        account: draft.account.trim(),
        label: draft.label.trim(),
        algorithm: draft.algorithm,
        digits: Number(draft.digits) as 6 | 8,
        period,
      };
      if (draft.secret.trim()) payload.secret = draft.secret.replace(/\s+/g, "").toUpperCase();
      await onSave(payload);
      onClose();
    } catch (saveError) {
      setError(friendlyError(saveError));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal-panel entry-dialog" role="dialog" aria-modal="true" aria-labelledby="entry-dialog-title">
        <div className="modal-head">
          <div>
            <p className="eyebrow">{entry ? "编辑条目" : "新增条目"}</p>
            <h2 id="entry-dialog-title">{entry ? "更新验证器" : "添加 TOTP"}</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="关闭"><X size={16} aria-hidden="true" /></button>
        </div>
        {!entry && (
          <>
            <div className="uri-import-box">
              <div className="field-label-row">
                <label htmlFor="otpauth-uri">粘贴 otpauth URI</label>
                <button className="text-button" type="button" onClick={() => setShowScanner(true)}>
                  <ScanLine size={13} aria-hidden="true" />
                  扫描二维码
                </button>
              </div>
              <textarea
                id="otpauth-uri"
                rows={2}
                value={draft.uri}
                onChange={(event) => handleUri(event.target.value)}
                placeholder="otpauth://totp/…"
                spellCheck={false}
              />
              {uriHint && <p className="field-hint">{uriHint}</p>}
            </div>
            <QrPasteZone onDecoded={handleScan} />
          </>
        )}
        {showScanner && <QrScanner onDecoded={handleScan} onClose={() => setShowScanner(false)} />}
        <form onSubmit={submit} className="entry-form">
          <div className="form-grid">
            <label>
              发行方
              <input value={draft.issuer} onChange={(event) => setField("issuer", event.target.value)} placeholder="GitHub" maxLength={120} />
            </label>
            <label>
              账户
              <input value={draft.account} onChange={(event) => setField("account", event.target.value)} placeholder="你@example.com" maxLength={200} required />
            </label>
            <label className="wide-field">
              名称
              <input value={draft.label} onChange={(event) => setField("label", event.target.value)} placeholder="个人 GitHub" maxLength={120} />
            </label>
            <label className="wide-field">
              TOTP 密钥（Secret） {entry && <span className="field-optional">留空以保留当前密钥</span>}
              <span className="secret-input-wrap">
                <input
                  type={showSecret ? "text" : "password"}
                  value={draft.secret}
                  onChange={(event) => setField("secret", event.target.value)}
                  placeholder={entry ? "当前密钥保持不变" : "JBSWY3DPEHPK3PXP"}
                  spellCheck={false}
                  autoComplete="off"
                />
                <button className="field-action" type="button" onClick={() => setShowSecret((current) => !current)}>{showSecret ? "隐藏" : "显示"}</button>
              </span>
              <span className="field-hint">将自动去除空格并规范化 Base32。</span>
            </label>
            <label>
              算法
              <Segmented
                label="算法"
                value={draft.algorithm}
                options={[
                  { value: "SHA1", label: "SHA1" },
                  { value: "SHA256", label: "SHA256" },
                  { value: "SHA512", label: "SHA512" },
                ]}
                onChange={(value) => setField("algorithm", value)}
              />
            </label>
            <label>
              位数
              <Segmented
                label="位数"
                value={draft.digits}
                options={[
                  { value: "6", label: "6 位" },
                  { value: "8", label: "8 位" },
                ]}
                onChange={(value) => setField("digits", value)}
              />
            </label>
            <label>
              周期
              <div className="input-with-suffix">
                <input type="number" min={1} max={86400} value={draft.period} onChange={(event) => setField("period", event.target.value)} />
                <span>秒</span>
              </div>
            </label>
          </div>
          {error && <p className="form-error" role="alert">{error}</p>}
          <div className="modal-actions">
            <button className="secondary-button" type="button" onClick={onClose}>取消</button>
            <button className="primary-button" type="submit" disabled={busy}>{busy ? "保存中…" : entry ? "保存修改" : "添加条目"}</button>
          </div>
        </form>
      </section>
    </div>
  );
}

interface SettingsModalProps {
  onClose: () => void;
  onImported: (count: number) => void;
  onNotify: (message: string, kind?: NoticeKind) => void;
}

function parseImportText(raw: string): ExportFile {
  try {
    const parsed = JSON.parse(raw) as ExportFile;
    if (parsed && parsed.version === 1 && Array.isArray(parsed.entries)) return parsed;
  } catch {
    // Try the deliberately small one-URI-per-line format below.
  }
  const entries: ExportEntry[] = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => parseOtpAuthUri(line))
    .filter((value): value is ParsedOtpAuth => value !== null)
    .map((value) => ({ ...value }));
  if (!entries.length) throw new Error("请选择 Totem JSON 导出文件，或每行一个 otpauth URI 的文本文件。");
  return { version: 1, createdAt: new Date().toISOString(), entries };
}

function SettingsModal({ onClose, onImported, onNotify }: SettingsModalProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const exportData = async () => {
    if (!window.confirm("导出文件包含明文 TOTP 密钥，请妥善保管。")) return;
    setError("");
    setBusy(true);
    try {
      const data = await api.exportEntries();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "totem-export.json";
      link.click();
      URL.revokeObjectURL(url);
      onNotify("导出文件已下载，请存放在安全位置。", "success");
    } catch (exportError) {
      setError(friendlyError(exportError));
    } finally {
      setBusy(false);
    }
  };

  const importFile = async (file: File) => {
    setError("");
    setBusy(true);
    try {
      const payload = parseImportText(await file.text());
      const result = await api.importEntries(payload);
      onImported(result.imported);
    } catch (importError) {
      setError(friendlyError(importError));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal-panel settings-dialog" role="dialog" aria-modal="true" aria-labelledby="settings-title">
        <div className="modal-head">
          <div>
            <p className="eyebrow">维护</p>
            <h2 id="settings-title">导入与导出</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="关闭"><X size={16} aria-hidden="true" /></button>
        </div>
        <div className="settings-block">
          <div>
            <h3>导出备份</h3>
            <p>导出的文件包含明文 TOTP 密钥，请将 JSON 文件离线安全保存。</p>
          </div>
          <button className="secondary-button" type="button" onClick={() => void exportData()} disabled={busy}>
            <Download size={14} aria-hidden="true" />
            下载 JSON
          </button>
        </div>
        <div className="settings-divider" />
        <div className="settings-block">
          <div>
            <h3>导入条目</h3>
            <p>导入 Totem JSON 文件，或每行一个 otpauth:// URI 的文本文件。</p>
          </div>
          <label className="file-button">
            <Download size={14} aria-hidden="true" style={{ transform: "rotate(180deg)" }} />
            <span>{busy ? "导入中…" : "选择文件"}</span>
            <input type="file" accept=".json,.txt,application/json,text/plain" disabled={busy} onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void importFile(file);
              event.currentTarget.value = "";
            }} />
          </label>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </div>
  );
}

interface TotpCardProps {
  entry: TotpEntry;
  now: number;
  onCopy: (entry: TotpEntry) => void;
  onEdit: (entry: TotpEntry) => void;
  onCopyAccount: (account: string) => void;
  onSecret: (entry: TotpEntry) => void;
  onUri: (entry: TotpEntry) => void;
  onDelete: (entry: TotpEntry) => void;
}

function TotpCard({ entry, now, onCopy, onEdit, onCopyAccount, onSecret, onUri, onDelete }: TotpCardProps) {
  const remaining = remainingSeconds(entry, now);
  const progress = Math.min(1, remaining / entry.period);
  const ringRadius = 16;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const menuRef = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    const closeOnOutsideClick = (event: PointerEvent) => {
      if (menuRef.current?.open && !menuRef.current.contains(event.target as Node)) {
        menuRef.current.open = false;
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape" && menuRef.current?.open) {
        menuRef.current.open = false;
      }
    };
    document.addEventListener("pointerdown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  return (
    <article className={`totp-card ${remaining <= 5 ? "is-expiring" : ""}`}>
      <div className="card-topline">
        <div className="entry-identity">
          <div>
            <h2>
              <button
                className="account-copy-button"
                type="button"
                onClick={() => onCopyAccount(entry.account)}
                aria-label={`复制邮箱 ${entry.account}`}
                title="点击复制邮箱"
              >
                {entry.account || entry.label || "未命名条目"}
              </button>
            </h2>
          </div>
        </div>
        <details ref={menuRef} className="entry-menu">
          <summary aria-label={`操作：${entry.label || entry.account}`}>
            <Ellipsis size={18} aria-hidden="true" />
          </summary>
          <div className="menu-popover">
            <button type="button" onClick={() => onEdit(entry)}>
              <Pencil size={14} aria-hidden="true" />
              编辑条目
            </button>
            <button type="button" onClick={() => onSecret(entry)}>
              <Eye size={14} aria-hidden="true" />
              显示密钥
            </button>
            <button type="button" onClick={() => onUri(entry)}>
              <Link2 size={14} aria-hidden="true" />
              复制 otpauth URI
            </button>
            <button className="danger-menu-item" type="button" onClick={() => onDelete(entry)}>
              <Trash2 size={14} aria-hidden="true" />
              删除
            </button>
          </div>
        </details>
      </div>
      <div className="code-row">
        <button className="code-button" type="button" onClick={() => onCopy(entry)} aria-label={`复制验证码 ${entry.code}`}>
          {formatCode(entry.code, entry.digits)}
        </button>
        <div className={`countdown ${remaining <= 5 ? "warning" : ""}`}>
          <svg className="countdown-ring" viewBox="0 0 40 40" aria-hidden="true">
            <circle className="ring-track" cx="20" cy="20" r={ringRadius} />
            <circle
              className="ring-value"
              cx="20"
              cy="20"
              r={ringRadius}
              strokeDasharray={ringCircumference}
              strokeDashoffset={ringCircumference * (1 - progress)}
            />
          </svg>
          <span className="countdown-num">{remaining}</span>
        </div>
      </div>
      <div className="card-meta"><span>{entry.issuer || "自定义发行方"}</span><span>{entry.algorithm} · {entry.period}秒</span></div>
    </article>
  );
}

function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [entries, setEntries] = useState<TotpEntry[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [search, setSearch] = useState("");
  const [dialog, setDialog] = useState<{ mode: "add" | "edit"; entry?: TotpEntry } | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [revealed, setRevealed] = useState<{ title: string; secret: string } | null>(null);
  const [notices, setNotices] = useState<AppNotice[]>([]);
  const noticeId = useRef(0);
  const modalOpen = Boolean(dialog || settingsOpen || revealed);

  const notify = useCallback((message: string, kind: NoticeKind = "info") => {
    const id = noticeId.current + 1;
    noticeId.current = id;
    setNotices((current) => [...current, { id, message, kind }].slice(-5));
    window.setTimeout(() => {
      setNotices((current) => current.filter((notice) => notice.id !== id));
    }, 2800);
  }, []);

  useEffect(() => {
    void api.getSession()
      .then((result) => setAuthenticated(result.authenticated))
      .catch(() => setAuthenticated(false));
  }, []);

  useEffect(() => {
    if (!authenticated) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [authenticated]);

  const applyEntries = useCallback((nextEntries: TotpEntry[]) => {
    setEntries(nextEntries);
  }, []);
  useTotpStream(authenticated === true, applyEntries);

  useEffect(() => {
    if (!authenticated) {
      setEntries([]);
      return undefined;
    }
    void api.getEntries().then(setEntries).catch((error) => {
      if (error instanceof ApiError && error.status === 401) setAuthenticated(false);
    });
    return undefined;
  }, [authenticated]);

  const filteredEntries = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return entries;
    return entries.filter((entry) => [entry.issuer, entry.account, entry.label].some((value) => value.toLowerCase().includes(query)));
  }, [entries, search]);

  const handleLogin = async (password: string) => {
    await api.login(password);
    setAuthenticated(true);
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } finally {
      setAuthenticated(false);
    }
  };

  const handleSave = async (payload: EntryPayload) => {
    if (dialog?.mode === "edit" && dialog.entry) {
      await api.updateEntry(dialog.entry.id, payload);
      notify("条目已更新", "success");
    } else {
      await api.createEntry(payload);
      notify("条目已添加", "success");
    }
    const latest = await api.getEntries();
    setEntries(latest);
  };

  const handleCopy = async (entry: TotpEntry) => {
    try {
      await navigator.clipboard.writeText(entry.code);
    } catch {
      const input = document.createElement("input");
      input.value = entry.code;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      input.remove();
    }
    notify("验证码已复制", "success");
  };

  const handleCopyAccount = async (account: string) => {
    try {
      await navigator.clipboard.writeText(account);
    } catch {
      const input = document.createElement("input");
      input.value = account;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      input.remove();
    }
    notify("邮箱已复制", "success");
  };

  const handleSecret = async (entry: TotpEntry) => {
    try {
      const result = await api.getSecret(entry.id);
      setRevealed({ title: entry.label || entry.account, secret: result.secret });
    } catch (error) {
      notify(friendlyError(error), "error");
    }
  };

  const handleUri = async (entry: TotpEntry) => {
    try {
      const result = await api.getOtpAuthUri(entry.id);
      await navigator.clipboard.writeText(result.uri);
      notify("otpauth URI 已复制", "success");
    } catch (error) {
      notify(friendlyError(error), "error");
    }
  };

  const handleDelete = async (entry: TotpEntry) => {
    if (!window.confirm(`确定删除“${entry.label || entry.account}”吗？\n\n此操作无法撤销。`)) return;
    try {
      await api.deleteEntry(entry.id);
      setEntries((current) => current.filter((item) => item.id !== entry.id));
      notify("条目已删除", "success");
    } catch (error) {
      notify(friendlyError(error), "error");
    }
  };

  if (authenticated === null) {
    return <div className="loading-screen"><img className="brand-mark" src="/totem.svg" alt="" aria-hidden="true" /><span>正在加载 Totem…</span></div>;
  }
  if (!authenticated) return <LoginScreen onLogin={handleLogin} />;

  return (
    <div className={`app-shell${modalOpen ? " modal-open" : ""}`}>
      <header className="app-header">
        <div className="header-left">
          <div className="brand-lockup"><img className="brand-mark" src="/totem.svg" alt="" aria-hidden="true" /><span>Totem</span></div>
        </div>
        <div className="header-tools">
          <label className="search-box">
            <Search size={13} aria-hidden="true" />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索条目…" aria-label="搜索条目" />
            {search && <button type="button" className="clear-search" onClick={() => setSearch("")} aria-label="清除搜索"><X size={13} aria-hidden="true" /></button>}
          </label>
          <button className="secondary-button settings-button" type="button" onClick={() => setSettingsOpen(true)} aria-label="设置">
            <Settings size={14} aria-hidden="true" />
            <span>设置</span>
          </button>
          <button className="primary-button add-button" type="button" onClick={() => setDialog({ mode: "add" })}>
            <Plus size={14} strokeWidth={2.5} aria-hidden="true" />
            <span>添加</span>
          </button>
          <button className="icon-button logout-button" type="button" onClick={() => void handleLogout()} aria-label="退出登录" title="退出登录">
            <LogOut size={15} aria-hidden="true" />
          </button>
        </div>
      </header>
      <main className="content-shell">
        {entries.length > 0 && <div className="results-line">{filteredEntries.length} 个条目{search && `，匹配“${search}”`}</div>}
        {filteredEntries.length > 0 ? (
          <section className="entry-grid" aria-label="TOTP 条目">
            {filteredEntries.map((entry) => <TotpCard key={entry.id} entry={entry} now={now} onCopy={handleCopy} onEdit={(item) => setDialog({ mode: "edit", entry: item })} onCopyAccount={handleCopyAccount} onSecret={handleSecret} onUri={handleUri} onDelete={handleDelete} />)}
          </section>
        ) : (
          <section className="empty-state">
            <div className="empty-icon"><KeyRound size={24} strokeWidth={1.75} aria-hidden="true" /></div>
            <h2>{entries.length === 0 ? "还没有验证器条目" : "没有匹配的条目"}</h2>
            <p>{entries.length === 0 ? "添加 otpauth URI 或手动输入 Secret 开始使用。" : "请尝试其他发行方、账户或名称。"}</p>
            {entries.length === 0 && (
              <button className="primary-button" type="button" onClick={() => setDialog({ mode: "add" })}>
                <Plus size={14} strokeWidth={2.5} aria-hidden="true" />
                添加第一个条目
              </button>
            )}
          </section>
        )}
      </main>
      {dialog && <EntryDialog entry={dialog.entry} onClose={() => setDialog(null)} onSave={handleSave} />}
      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} onNotify={notify} onImported={(count) => notify(`已导入 ${count} 个条目`, "success")} />}
      {revealed && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setRevealed(null)}>
          <section className="modal-panel secret-dialog" role="dialog" aria-modal="true" aria-labelledby="secret-title">
            <div className="modal-head"><div><p className="eyebrow">敏感数据</p><h2 id="secret-title">{revealed.title}</h2></div><button className="icon-button" type="button" onClick={() => setRevealed(null)} aria-label="关闭"><X size={16} aria-hidden="true" /></button></div>
            <p className="secret-warning">这是解密后的 TOTP Secret，请勿分享，也不要留在不安全的截图中。</p>
            <code className="secret-value">{revealed.secret}</code>
            <div className="modal-actions"><button className="secondary-button" type="button" onClick={() => setRevealed(null)}>关闭</button></div>
          </section>
        </div>
      )}
      {notices.length > 0 && (
        <div className="notice-stack" aria-live="polite" aria-atomic="false">
          {notices.map((notice) => (
            <div key={notice.id} className={`global-notice notice-${notice.kind}`} role={notice.kind === "error" ? "alert" : "status"}>
              {notice.message}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;
