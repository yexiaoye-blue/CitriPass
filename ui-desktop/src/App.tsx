import { useEffect, useState } from "react";
import {
  createFolder,
  createLogin,
  createNote,
  createTotp,
  createVault,
  deleteItem,
  errorText,
  generatePassword,
  inDesktop,
  lockVault,
  searchItems,
  setIdleMinutes,
  syncVault,
  touchVault,
  unlockVault,
  updateFolder,
  updateLogin,
  updateNote,
  updateTotp,
  vaultStatus,
  type HostStatus,
  type ItemView,
  type SyncView,
} from "./api";

const DEFAULT_ENDPOINT = "http://127.0.0.1:18081";

export function App() {
  const desktop = inDesktop();
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  useEffect(() => {
    if (!desktop) {
      return;
    }
    let cancelled = false;
    vaultStatus()
      .then((next) => {
        if (!cancelled) {
          setStatus(next);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(errorText(caught));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [desktop]);

  useEffect(() => {
    if (!desktop || status?.phase !== "unlocked") {
      return;
    }
    const timer = window.setInterval(() => {
      vaultStatus()
        .then((next) => setStatus(next))
        .catch(() => undefined);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [desktop, status?.phase]);

  useEffect(() => {
    if (!desktop || status?.phase !== "unlocked") {
      return;
    }
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last < 15000) {
        return;
      }
      last = now;
      void touchVault();
    };
    window.addEventListener("pointerdown", onActivity, { passive: true });
    window.addEventListener("keydown", onActivity);
    return () => {
      window.removeEventListener("pointerdown", onActivity);
      window.removeEventListener("keydown", onActivity);
    };
  }, [desktop, status?.phase]);

  async function run(action: () => Promise<HostStatus>): Promise<boolean> {
    setError("");
    setBusy(true);
    try {
      setStatus(await action());
      setRefreshToken((value) => value + 1);
      return true;
    } catch (caught) {
      setError(errorText(caught));
      try {
        setStatus(await vaultStatus());
      } catch {
        // Keep the status already on screen.
      }
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function onCreate(password: string) {
    setError("");
    setBusy(true);
    try {
      const created = await createVault(password);
      setRecoveryKey(created.recoveryKey);
      setStatus(created.status);
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setBusy(false);
    }
  }

  const phase = status?.phase ?? "empty";

  return (
    <main className="page" aria-busy={busy}>
      <header>
        <h1>CitriPass</h1>
        <p className="lede">
          这台电脑上的一本保险库。可以记下登录、笔记和验证码，放进文件夹，标成收藏，也可以同步到本机的同步服务。
        </p>
      </header>
      {recoveryKey ? (
        <RecoveryNotice recoveryKey={recoveryKey} onClear={() => setRecoveryKey(null)} />
      ) : null}
      {!desktop ? (
        <p className="alert" role="alert">
          当前页面不在桌面程序里。先构建页面，再从桌面程序打开。
        </p>
      ) : null}
      {error ? (
        <p className="alert" role="alert">
          {error}
        </p>
      ) : null}
      {status?.idleLocked && phase !== "unlocked" ? (
        <p className="alert" role="status">
          空闲时间到了，保险库已锁定。请重新输入主密码。
        </p>
      ) : null}
      {!status && desktop ? <p className="empty">正在打开保险库。</p> : null}
      {status && phase === "empty" ? (
        <CreateForm busy={busy || !desktop} onCreate={onCreate} />
      ) : null}
      {status && phase === "locked" ? (
        <UnlockForm
          busy={busy || !desktop}
          idleMinutes={status.idleMinutes}
          onUnlock={(password) => run(() => unlockVault(password))}
          onIdle={(minutes) => run(() => setIdleMinutes(minutes))}
        />
      ) : null}
      {status && phase === "unlocked" ? (
        <Workspace
          status={status}
          busy={busy || !desktop}
          refreshToken={refreshToken}
          onRun={run}
          onReport={setError}
        />
      ) : null}
    </main>
  );
}

function RecoveryNotice({
  recoveryKey,
  onClear,
}: {
  recoveryKey: string;
  onClear: () => void;
}) {
  return (
    <section className="recovery" aria-labelledby="recovery-title">
      <h2 id="recovery-title">恢复密钥只显示这一次</h2>
      <p>写到你自己保管的地方。清除之后，界面、磁盘和日志里都不再留这份密钥。</p>
      <p className="recovery-key">{recoveryKey}</p>
      <button type="button" onClick={onClear}>
        我已记下，从界面清除
      </button>
    </section>
  );
}

function CreateForm({
  busy,
  onCreate,
}: {
  busy: boolean;
  onCreate: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [localError, setLocalError] = useState("");

  async function submit() {
    if (password !== again) {
      setLocalError("两次主密码不一致");
      return;
    }
    const secret = password;
    setPassword("");
    setAgain("");
    setLocalError("");
    await onCreate(secret);
  }

  return (
    <form
      className="gate"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <h2>创建保险库</h2>
      <p>主密码只用于这一次创建，提交后会从输入框清掉。</p>
      {localError ? (
        <p className="alert" role="alert">
          {localError}
        </p>
      ) : null}
      <label>
        主密码
        <input
          type="password"
          value={password}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setPassword(event.target.value)}
        />
      </label>
      <label>
        再输入一次
        <input
          type="password"
          value={again}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setAgain(event.target.value)}
        />
      </label>
      <div className="actions">
        <button className="primary" type="submit" disabled={busy || password.length === 0}>
          创建保险库
        </button>
      </div>
    </form>
  );
}

function UnlockForm({
  busy,
  idleMinutes,
  onUnlock,
  onIdle,
}: {
  busy: boolean;
  idleMinutes: number;
  onUnlock: (password: string) => Promise<boolean>;
  onIdle: (minutes: number) => Promise<boolean>;
}) {
  const [password, setPassword] = useState("");

  async function submit() {
    const secret = password;
    setPassword("");
    await onUnlock(secret);
  }

  return (
    <section className="gate">
      <h2>解锁保险库</h2>
      <p>锁定后需要重新输入主密码。库密钥不留在内存里。</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <label>
          主密码
          <input
            type="password"
            value={password}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <div className="actions">
          <button className="primary" type="submit" disabled={busy || password.length === 0}>
            解锁
          </button>
        </div>
      </form>
      <IdleControl minutes={idleMinutes} busy={busy} onApply={onIdle} />
    </section>
  );
}

function IdleControl({
  minutes,
  busy,
  onApply,
}: {
  minutes: number;
  busy: boolean;
  onApply: (minutes: number) => Promise<boolean>;
}) {
  const [draft, setDraft] = useState(String(minutes));
  const parsed = Number(draft);
  const valid = Number.isInteger(parsed) && parsed >= 1 && parsed <= 240;

  return (
    <form
      className="idle"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) {
          void onApply(parsed);
        }
      }}
    >
      <label>
        空闲后锁定（分钟）
        <input
          type="number"
          min={1}
          max={240}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
        />
      </label>
      <button type="submit" disabled={busy || !valid || parsed === minutes}>
        应用
      </button>
      <p>默认 5 分钟。到时间后丢掉内存中的库密钥。</p>
    </form>
  );
}

function Workspace({
  status,
  busy,
  refreshToken,
  onRun,
  onReport,
}: {
  status: HostStatus;
  busy: boolean;
  refreshToken: number;
  onRun: (action: () => Promise<HostStatus>) => Promise<boolean>;
  onReport: (message: string) => void;
}) {
  const [view, setView] = useState("all");
  const [selectedId, setSelectedId] = useState("");
  const [editorKey, setEditorKey] = useState(0);
  const [query, setQuery] = useState("");
  const [matches, setMatches] = useState<ItemView[] | null>(null);
  const [endpoint, setEndpoint] = useState(DEFAULT_ENDPOINT);
  const folders = orderedFolders(status.items.filter((item) => item.kind === "文件夹"));
  const folderIds = new Set(folders.map((folder) => folder.itemId));
  const activeFolder = folderIds.has(view) ? view : null;
  const mode = view === "favorite" ? "favorite" : activeFolder ? "folder" : "all";
  const catalog = new Map(status.items.map((item) => [item.itemId, item]));
  const base = matches
    ? matches.map((item) => catalog.get(item.itemId) ?? item)
    : status.items;
  const visible = base
    .filter((item) => {
      if (mode === "favorite" && !item.favorite) {
        return false;
      }
      if (mode === "folder" && item.folderId !== activeFolder && item.itemId !== activeFolder) {
        return false;
      }
      if (!query.trim() && item.kind === "文件夹") {
        return false;
      }
      return true;
    })
    .sort((left, right) => left.title.localeCompare(right.title, "zh"));
  const selected = status.items.find((item) => item.itemId === selectedId) ?? null;

  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed) {
      setMatches(null);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      searchItems(trimmed)
        .then((items) => {
          if (!cancelled) {
            setMatches(items);
          }
        })
        .catch((caught) => {
          if (!cancelled) {
            onReport(errorText(caught));
          }
        });
    }, 160);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query, refreshToken, onReport]);

  function openItem(item: ItemView) {
    if (item.kind === "文件夹") {
      setView(item.itemId);
      setSelectedId("");
      setEditorKey((value) => value + 1);
      return;
    }
    setSelectedId(item.itemId);
  }

  return (
    <div className="workspace">
      <nav className="rail" aria-label="文件夹">
        <div className="folder-list">
          <button
            type="button"
            className={mode === "all" ? "folder-button active" : "folder-button"}
            onClick={() => setView("all")}
          >
            全部条目
          </button>
          <button
            type="button"
            className={mode === "favorite" ? "folder-button active" : "folder-button"}
            onClick={() => setView("favorite")}
          >
            收藏
          </button>
          {folders.map((folder) => (
            <button
              key={folder.itemId}
              type="button"
              className={activeFolder === folder.itemId ? "folder-button active" : "folder-button"}
              style={{ paddingLeft: 10 + folderDepth(folder, catalog) * 14 }}
              onClick={() => setView(folder.itemId)}
            >
              {folder.title}
            </button>
          ))}
        </div>
        {activeFolder ? (
          <FolderEditor
            key={activeFolder}
            folder={catalog.get(activeFolder) ?? null}
            folders={folders}
            busy={busy}
            onRun={onRun}
            onRemoved={() => {
              setView("all");
              setSelectedId("");
            }}
          />
        ) : null}
        <NewFolder folders={folders} busy={busy} onRun={onRun} />
        <IdleControl
          key={status.idleMinutes}
          minutes={status.idleMinutes}
          busy={busy}
          onApply={(minutes) => onRun(() => setIdleMinutes(minutes))}
        />
        <form
          className="sync"
          onSubmit={(event) => {
            event.preventDefault();
            void onRun(() => syncVault(endpoint));
          }}
        >
          <label>
            同步服务
            <input
              value={endpoint}
              spellCheck={false}
              autoComplete="off"
              onChange={(event) => setEndpoint(event.target.value)}
            />
          </label>
          <button className="primary" type="submit" disabled={busy}>
            同步
          </button>
          <SyncLine report={status.lastSync} />
        </form>
        <details>
          <summary>这台设备</summary>
          <dl className="meta">
            <div>
              <dt>保险库</dt>
              <dd className="ids">{status.vaultId ?? "还没有"}</dd>
            </div>
            <div>
              <dt>设备</dt>
              <dd className="ids">{status.deviceId ?? "还没有"}</dd>
            </div>
            <div>
              <dt>数据库</dt>
              <dd>{status.databasePath}</dd>
            </div>
          </dl>
        </details>
        <button type="button" onClick={() => void onRun(() => lockVault())} disabled={busy}>
          锁定
        </button>
      </nav>
      <section className="sheet" aria-labelledby="entries-title">
        <div className="sheet-head">
          <h2 id="entries-title">{sheetTitle(mode, activeFolder, catalog)}</h2>
          <button
            type="button"
            onClick={() => {
              setSelectedId("");
              setEditorKey((value) => value + 1);
            }}
          >
            新建条目
          </button>
        </div>
        <label>
          搜索标题、备注或用户名
          <input
            value={query}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <ItemList items={visible} selectedId={selectedId} onOpen={openItem} />
        <ItemEditor
          key={(selectedId || "new") + "-" + String(editorKey)}
          selected={selected && selected.kind !== "文件夹" ? selected : null}
          folders={folders}
          defaultFolderId={activeFolder}
          busy={busy}
          onRun={onRun}
          onReset={() => {
            setSelectedId("");
            setEditorKey((value) => value + 1);
          }}
          onDelete={async (itemId) => {
            const removed = await onRun(() => deleteItem(itemId));
            if (removed) {
              setSelectedId("");
              setEditorKey((value) => value + 1);
            }
          }}
        />
      </section>
    </div>
  );
}

function sheetTitle(mode: string, folderId: string | null, catalog: Map<string, ItemView>) {
  if (mode === "favorite") {
    return "收藏";
  }
  if (mode === "folder" && folderId) {
    return catalog.get(folderId)?.title ?? "文件夹";
  }
  return "全部条目";
}

function ItemList({
  items,
  selectedId,
  onOpen,
}: {
  items: ItemView[];
  selectedId: string;
  onOpen: (item: ItemView) => void;
}) {
  if (items.length === 0) {
    return <p className="empty">这里还没有条目。可以新建一条登录、笔记或验证码。</p>;
  }
  return (
    <ul className="items">
      {items.map((item) => {
        const classes = ["item-row"];
        if (item.itemId === selectedId) {
          classes.push("selected");
        }
        if (item.conflictCopy) {
          classes.push("conflict");
        }
        return (
          <li key={item.itemId}>
            <button type="button" className={classes.join(" ")} onClick={() => onOpen(item)}>
              <span>
                <strong>{item.title}</strong>
                <span className="item-meta">
                  {item.kind}
                  {item.username ? " · " + item.username : ""}
                  {item.passwords.length > 0
                    ? " · " + item.passwords.map((entry) => entry.name).join("、")
                    : ""}
                  {item.favorite ? " · 收藏" : ""}
                </span>
              </span>
              {item.totpCode ? (
                <span className="otp">
                  {item.totpCode}
                  {item.totpRemaining !== null ? <span>{item.totpRemaining} 秒</span> : null}
                </span>
              ) : null}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

type PasswordDraft = {
  name: string;
  password: string;
  visible: boolean;
};

type FieldDraft = {
  name: string;
  value: string;
  concealed: boolean;
  visible: boolean;
};

function ItemEditor({
  selected,
  folders,
  defaultFolderId,
  busy,
  onRun,
  onReset,
  onDelete,
}: {
  selected: ItemView | null;
  folders: ItemView[];
  defaultFolderId: string | null;
  busy: boolean;
  onRun: (action: () => Promise<HostStatus>) => Promise<boolean>;
  onReset: () => void;
  onDelete: (itemId: string) => Promise<void>;
}) {
  const fixedKind = selected ? kindOf(selected) : null;
  const [kind, setKind] = useState(fixedKind ?? "login");
  const [title, setTitle] = useState(selected?.title ?? "");
  const [username, setUsername] = useState(selected?.username ?? "");
  const [passwords, setPasswords] = useState<PasswordDraft[]>(() =>
    selected
      ? selected.passwords.map((entry) => ({
          name: entry.name,
          password: entry.password,
          visible: false,
        }))
      : [{ name: "密码", password: "", visible: false }],
  );
  const [fields, setFields] = useState<FieldDraft[]>(() =>
    (selected?.customFields ?? []).map((field) => ({
      name: field.name,
      value: field.value,
      concealed: field.concealed,
      visible: false,
    })),
  );
  const [notes, setNotes] = useState(selected?.notes ?? "");
  const [secret, setSecret] = useState(selected?.totpSecret ?? "");
  const [folderId, setFolderId] = useState(selected?.folderId ?? defaultFolderId ?? "");
  const [favorite, setFavorite] = useState(selected?.favorite ?? false);
  const [length, setLength] = useState("24");
  const [confirming, setConfirming] = useState(false);
  const [localError, setLocalError] = useState("");
  const shownKind = fixedKind ?? kind;

  async function save() {
    const folder = folderId || null;
    if (fields.some((field) => field.name.trim().length === 0)) {
      setLocalError("自定义字段的名称不能是空白");
      return;
    }
    if (shownKind === "login" && passwords.some((entry) => entry.name.trim().length === 0)) {
      setLocalError("密码名称不能是空白");
      return;
    }
    const customFields = fields.map((field) => ({
      name: field.name,
      value: field.value,
      concealed: field.concealed,
    }));
    const passwordList = passwords.map((entry) => ({
      name: entry.name,
      password: entry.password,
    }));
    if (selected) {
      if (shownKind === "note") {
        await onRun(() => updateNote(selected.itemId, title, notes, customFields, folder, favorite));
      } else if (shownKind === "totp") {
        await onRun(() =>
          updateTotp(selected.itemId, title, secret, notes, customFields, folder, favorite),
        );
      } else {
        await onRun(() =>
          updateLogin(
            selected.itemId,
            title,
            username,
            passwordList,
            notes,
            customFields,
            folder,
            favorite,
          ),
        );
      }
      return;
    }
    const created =
      shownKind === "note"
        ? await onRun(() => createNote(title, notes, customFields, folder, favorite))
        : shownKind === "totp"
          ? await onRun(() => createTotp(title, secret, notes, customFields, folder, favorite))
          : await onRun(() =>
              createLogin(title, username, passwordList, notes, customFields, folder, favorite),
            );
    if (created) {
      onReset();
    }
  }

  async function fillPassword(index: number) {
    setLocalError("");
    try {
      const generated = await generatePassword(Number(length));
      setPasswords((current) =>
        current.map((entry, entryIndex) =>
          entryIndex === index ? { ...entry, password: generated } : entry,
        ),
      );
    } catch (caught) {
      setLocalError(errorText(caught));
    }
  }

  return (
    <form
      className="editor"
      onSubmit={(event) => {
        event.preventDefault();
        void save();
      }}
    >
      <h2>{selected ? "编辑条目" : "新条目"}</h2>
      {localError ? (
        <p className="alert" role="alert">
          {localError}
        </p>
      ) : null}
      {selected ? null : (
        <fieldset className="kind">
          <legend>类型</legend>
          <label>
            <input
              type="radio"
              name="kind"
              checked={shownKind === "login"}
              onChange={() => setKind("login")}
            />
            登录
          </label>
          <label>
            <input
              type="radio"
              name="kind"
              checked={shownKind === "note"}
              onChange={() => setKind("note")}
            />
            笔记
          </label>
          <label>
            <input
              type="radio"
              name="kind"
              checked={shownKind === "totp"}
              onChange={() => setKind("totp")}
            />
            验证码
          </label>
        </fieldset>
      )}
      <label>
        标题
        <input value={title} onChange={(event) => setTitle(event.target.value)} />
      </label>
      {shownKind === "login" ? (
        <label>
          用户名
          <input
            value={username}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setUsername(event.target.value)}
          />
        </label>
      ) : null}
      {shownKind === "login" ? (
        <fieldset className="repeat">
          <legend>密码</legend>
          {passwords.length === 0 ? <p className="hint">可以没有密码，也可以添加多条。</p> : null}
          {passwords.map((entry, index) => (
            <div className="repeat-row" key={index}>
              <label>
                名称
                <input
                  value={entry.name}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) =>
                    setPasswords((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, name: event.target.value } : item,
                      ),
                    )
                  }
                />
              </label>
              <label>
                密码
                <input
                  type={entry.visible ? "text" : "password"}
                  value={entry.password}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) =>
                    setPasswords((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, password: event.target.value } : item,
                      ),
                    )
                  }
                />
              </label>
              <div className="row-actions">
                <button
                  type="button"
                  onClick={() =>
                    setPasswords((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, visible: !item.visible } : item,
                      ),
                    )
                  }
                >
                  {entry.visible ? "隐藏" : "显示"}
                </button>
                <button type="button" onClick={() => void fillPassword(index)}>
                  生成
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setPasswords((current) => current.filter((_, itemIndex) => itemIndex !== index))
                  }
                >
                  删除
                </button>
              </div>
            </div>
          ))}
          <div className="row-actions">
            <button
              type="button"
              onClick={() =>
                setPasswords((current) => [
                  ...current,
                  { name: "密码", password: "", visible: false },
                ])
              }
            >
              添加密码
            </button>
            <label className="inline">
              长度
              <input
                type="number"
                min={8}
                max={1024}
                value={length}
                onChange={(event) => setLength(event.target.value)}
              />
            </label>
          </div>
        </fieldset>
      ) : null}
      <fieldset className="repeat">
        <legend>自定义字段</legend>
        {fields.length === 0 ? <p className="hint">名称、值和是否隐藏。可以一条都没有。</p> : null}
        {fields.map((field, index) => (
          <div className="repeat-row" key={index}>
            <label>
              名称
              <input
                value={field.name}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) =>
                  setFields((current) =>
                    current.map((item, itemIndex) =>
                      itemIndex === index ? { ...item, name: event.target.value } : item,
                    ),
                  )
                }
              />
            </label>
            <label>
              值
              <input
                type={field.concealed && !field.visible ? "password" : "text"}
                value={field.value}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) =>
                  setFields((current) =>
                    current.map((item, itemIndex) =>
                      itemIndex === index ? { ...item, value: event.target.value } : item,
                    ),
                  )
                }
              />
            </label>
            <div className="row-actions">
              <label className="check">
                <input
                  type="checkbox"
                  checked={field.concealed}
                  onChange={(event) =>
                    setFields((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, concealed: event.target.checked } : item,
                      ),
                    )
                  }
                />
                隐藏
              </label>
              <button
                type="button"
                onClick={() =>
                  setFields((current) =>
                    current.map((item, itemIndex) =>
                      itemIndex === index ? { ...item, visible: !item.visible } : item,
                    ),
                  )
                }
              >
                {field.visible ? "隐藏值" : "显示值"}
              </button>
              <button
                type="button"
                onClick={() => setFields((current) => current.filter((_, itemIndex) => itemIndex !== index))}
              >
                删除
              </button>
            </div>
          </div>
        ))}
        <div className="row-actions">
          <button
            type="button"
            onClick={() =>
              setFields((current) => [
                ...current,
                { name: "", value: "", concealed: false, visible: false },
              ])
            }
          >
            添加字段
          </button>
        </div>
      </fieldset>
      {shownKind === "totp" ? (
        <label>
          验证码密钥
          <input
            value={secret}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setSecret(event.target.value)}
          />
        </label>
      ) : null}
      <label>
        备注
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)} />
      </label>
      <label>
        文件夹
        <select value={folderId} onChange={(event) => setFolderId(event.target.value)}>
          <option value="">根目录</option>
          {folders.map((folder) => (
            <option key={folder.itemId} value={folder.itemId}>
              {folder.title}
            </option>
          ))}
        </select>
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={favorite}
          onChange={(event) => setFavorite(event.target.checked)}
        />
        收藏
      </label>
      <div className="actions">
        <button className="primary" type="submit" disabled={busy || title.trim().length === 0}>
          {selected ? "保存修改" : "创建条目"}
        </button>
        {selected ? (
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              if (!confirming) {
                setConfirming(true);
                return;
              }
              void onDelete(selected.itemId);
            }}
          >
            {confirming ? "确认删除" : "删除"}
          </button>
        ) : null}
      </div>
    </form>
  );
}

function FolderEditor({
  folder,
  folders,
  busy,
  onRun,
  onRemoved,
}: {
  folder: ItemView | null;
  folders: ItemView[];
  busy: boolean;
  onRun: (action: () => Promise<HostStatus>) => Promise<boolean>;
  onRemoved: () => void;
}) {
  const [title, setTitle] = useState(folder?.title ?? "");
  const [parentId, setParentId] = useState(folder?.folderParentId ?? "");
  const [confirming, setConfirming] = useState(false);
  if (!folder) {
    return null;
  }
  const banned = descendantIds(folder.itemId, folders);
  return (
    <form
      className="folder-editor"
      onSubmit={(event) => {
        event.preventDefault();
        void onRun(() => updateFolder(folder.itemId, title, parentId || null));
      }}
    >
      <h2>这个文件夹</h2>
      <label>
        名称
        <input value={title} onChange={(event) => setTitle(event.target.value)} />
      </label>
      <label>
        上级
        <select value={parentId} onChange={(event) => setParentId(event.target.value)}>
          <option value="">根目录</option>
          {folders
            .filter((item) => !banned.has(item.itemId))
            .map((item) => (
              <option key={item.itemId} value={item.itemId}>
                {item.title}
              </option>
            ))}
        </select>
      </label>
      <div className="actions">
        <button type="submit" disabled={busy || title.trim().length === 0}>
          保存文件夹
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            if (!confirming) {
              setConfirming(true);
              return;
            }
            void (async () => {
              const removed = await onRun(() => deleteItem(folder.itemId));
              if (removed) {
                onRemoved();
              }
            })();
          }}
        >
          {confirming ? "确认删除" : "删除文件夹"}
        </button>
      </div>
    </form>
  );
}

function NewFolder({
  folders,
  busy,
  onRun,
}: {
  folders: ItemView[];
  busy: boolean;
  onRun: (action: () => Promise<HostStatus>) => Promise<boolean>;
}) {
  const [title, setTitle] = useState("");
  const [parentId, setParentId] = useState("");
  return (
    <form
      className="folder-editor"
      onSubmit={(event) => {
        event.preventDefault();
        void (async () => {
          const created = await onRun(() => createFolder(title, parentId || null));
          if (created) {
            setTitle("");
          }
        })();
      }}
    >
      <h2>新文件夹</h2>
      <label>
        名称
        <input value={title} onChange={(event) => setTitle(event.target.value)} />
      </label>
      <label>
        上级
        <select value={parentId} onChange={(event) => setParentId(event.target.value)}>
          <option value="">根目录</option>
          {folders.map((folder) => (
            <option key={folder.itemId} value={folder.itemId}>
              {folder.title}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" disabled={busy || title.trim().length === 0}>
        创建文件夹
      </button>
    </form>
  );
}

function SyncLine({ report }: { report: SyncView | null }) {
  if (!report) {
    return <p>还没有同步。</p>;
  }
  return (
    <p>
      推送 {report.pushed}，接受 {report.accepted}，冲突 {report.conflicts}，拉取 {report.pulled}。
    </p>
  );
}

function orderedFolders(folders: ItemView[]): ItemView[] {
  const byParent = new Map<string, ItemView[]>();
  for (const folder of folders) {
    const key = folder.folderParentId ?? "";
    const list = byParent.get(key) ?? [];
    list.push(folder);
    byParent.set(key, list);
  }
  for (const list of byParent.values()) {
    list.sort((left, right) => left.title.localeCompare(right.title, "zh"));
  }
  const ordered: ItemView[] = [];
  const seen = new Set<string>();
  const walk = (parent: string) => {
    for (const folder of byParent.get(parent) ?? []) {
      if (seen.has(folder.itemId)) {
        continue;
      }
      seen.add(folder.itemId);
      ordered.push(folder);
      walk(folder.itemId);
    }
  };
  walk("");
  for (const folder of folders) {
    if (!seen.has(folder.itemId)) {
      ordered.push(folder);
    }
  }
  return ordered;
}

function folderDepth(folder: ItemView, catalog: Map<string, ItemView>): number {
  let depth = 0;
  let cursor = folder.folderParentId;
  const seen = new Set<string>();
  while (cursor) {
    if (seen.has(cursor) || depth > 12) {
      break;
    }
    seen.add(cursor);
    depth += 1;
    cursor = catalog.get(cursor)?.folderParentId ?? null;
  }
  return depth;
}

function descendantIds(rootId: string, folders: ItemView[]): Set<string> {
  const children = new Map<string, string[]>();
  for (const folder of folders) {
    if (!folder.folderParentId) {
      continue;
    }
    const list = children.get(folder.folderParentId) ?? [];
    list.push(folder.itemId);
    children.set(folder.folderParentId, list);
  }
  const banned = new Set<string>([rootId]);
  const stack = [rootId];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) {
      break;
    }
    for (const child of children.get(current) ?? []) {
      if (!banned.has(child)) {
        banned.add(child);
        stack.push(child);
      }
    }
  }
  return banned;
}

function kindOf(item: ItemView): "login" | "note" | "totp" {
  if (item.kind === "笔记") {
    return "note";
  }
  if (item.kind === "验证码") {
    return "totp";
  }
  return "login";
}
