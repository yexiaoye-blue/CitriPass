import { useEffect, useState } from "react";
import {
  createDeviceA,
  createLogin,
  createNote,
  createTotp,
  errorText,
  generatePassword,
  hostStatus,
  inDesktopHost,
  lockDevice,
  provisionDeviceB,
  syncDevice,
  updateLogin,
  updateNote,
  updateTotp,
  unlockDevice,
  type DeviceView,
  type HostStatus,
  type ItemView,
  type SyncView,
} from "./api";

const DEFAULT_ENDPOINT = "http://127.0.0.1:18081";

export function App() {
  const desktop = inDesktopHost();
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [endpoint, setEndpoint] = useState(DEFAULT_ENDPOINT);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);

  useEffect(() => {
    if (!desktop) {
      return;
    }
    let cancelled = false;
    hostStatus()
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

  const showsTotp =
    status?.devices.some(
      (device) => device.phase === "unlocked" && device.items.some((item) => item.totpCode),
    ) ?? false;
  useEffect(() => {
    if (!desktop || !showsTotp) {
      return;
    }
    const timer = window.setInterval(() => {
      hostStatus()
        .then((next) => setStatus(next))
        .catch(() => undefined);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [desktop, showsTotp]);

  async function run(action: () => Promise<HostStatus>) {
    setError("");
    setBusy(true);
    try {
      setStatus(await action());
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setBusy(false);
    }
  }

  const deviceA = status?.devices.find((device) => device.id === "a");
  const deviceB = status?.devices.find((device) => device.id === "b");

  return (
    <main className="page" aria-busy={busy}>
      <header className="mast">
        <h1>同一本保险库，两台设备</h1>
        <p className="lede">
          这是桌面验证宿主。可以创建保险库、锁定后再解锁、写笔记和登录条目，并在两台设备之间同步。它还不是完整的密码管理器。主密码只参与这一次操作，界面随后清掉。
        </p>
        {recoveryKey ? (
          <section className="recovery" aria-labelledby="recovery-title">
            <h2 id="recovery-title">恢复密钥只显示这一次</h2>
            <p>写下来或复制到你自己保管的地方。关掉这张提示后，宿主不再保存它。</p>
            <p className="recovery-key">{recoveryKey}</p>
            <button type="button" onClick={() => setRecoveryKey(null)}>
              我已记下
            </button>
          </section>
        ) : null}
        <label className="endpoint">
          同步服务
          <input
            value={endpoint}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => setEndpoint(event.target.value)}
          />
        </label>
        {status ? <p className="root">档案目录 {status.root}</p> : null}
      </header>

      {!desktop ? (
        <p className="alert" role="alert">
          当前页面不在 Tauri 宿主里，设备命令不可用。先启动桌面程序，再操作这两台设备。
        </p>
      ) : null}
      {error ? (
        <p className="alert" role="alert">
          {error}
        </p>
      ) : null}

      <div className="bench">
        <DevicePane
          id="a"
          name="设备 A"
          device={deviceA}
          endpoint={endpoint}
          busy={busy || !desktop}
          peerReady
          onRun={run}
          onRecovery={setRecoveryKey}
        />
        <aside className="spine">
          <h2>同步结果</h2>
          <p>
            先在两边改同一条目标题，再分别点同步。先到的写入服务器，后到的保留服务器条目，并把本地内容另存为标题以「冲突 」开头的新条目。
          </p>
          <SyncLine label="设备 A" report={deviceA?.lastSync ?? null} />
          <SyncLine label="设备 B" report={deviceB?.lastSync ?? null} />
        </aside>
        <DevicePane
          id="b"
          name="设备 B"
          device={deviceB}
          endpoint={endpoint}
          busy={busy || !desktop}
          peerReady={deviceA?.phase === "unlocked"}
          onRun={run}
          onRecovery={setRecoveryKey}
        />
      </div>
    </main>
  );
}

function SyncLine({ label, report }: { label: string; report: SyncView | null }) {
  if (!report) {
    return (
      <p className="sync-line">
        <strong>{label}</strong> 还没有同步。
      </p>
    );
  }
  return (
    <p className="sync-line">
      <strong>{label}</strong> 推送 {report.pushed}，接受 {report.accepted}，冲突 {report.conflicts}，拉取 {report.pulled}。游标 {report.cursor}。
    </p>
  );
}

function DevicePane({
  id,
  name,
  device,
  endpoint,
  busy,
  peerReady,
  onRun,
  onRecovery,
}: {
  id: string;
  name: string;
  device: DeviceView | undefined;
  endpoint: string;
  busy: boolean;
  peerReady: boolean;
  onRun: (action: () => Promise<HostStatus>) => Promise<void>;
  onRecovery: (recoveryKey: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");
  const [username, setUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [secret, setSecret] = useState("");
  const [length, setLength] = useState("24");
  const [newKind, setNewKind] = useState<"note" | "login" | "totp">("login");
  const [selectedId, setSelectedId] = useState("");
  const [draftTitle, setDraftTitle] = useState("");
  const [draftNotes, setDraftNotes] = useState("");
  const [draftUsername, setDraftUsername] = useState("");
  const [draftPassword, setDraftPassword] = useState("");
  const [draftSecret, setDraftSecret] = useState("");
  const phase = device?.phase ?? "empty";
  const selected = device?.items.find((item) => item.itemId === selectedId) ?? null;

  async function withPassword(action: (secret: string) => Promise<HostStatus>) {
    const secret = password;
    setPassword("");
    await onRun(() => action(secret));
  }

  return (
    <section className="device" aria-labelledby={`${id}-title`}>
      <h2 id={`${id}-title`}>{name}</h2>
      <dl className="meta">
        <div>
          <dt>数据库</dt>
          <dd>{device?.databasePath ?? "尚未打开"}</dd>
        </div>
        <div>
          <dt>附件目录</dt>
          <dd>{device?.attachmentDir ?? "尚未打开"}</dd>
        </div>
        <div>
          <dt>保险库</dt>
          <dd className="ids">{device?.vaultId ?? "还没有"}</dd>
        </div>
        <div>
          <dt>设备</dt>
          <dd className="ids">{device?.deviceId ?? "还没有"}</dd>
        </div>
      </dl>

      {phase === "unlocked" ? (
        <p>已解锁。主密码已从界面清掉。</p>
      ) : (
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
      )}

      <div className="actions">
        {id === "a" && phase === "empty" ? (
          <button
            className="primary"
            type="button"
            disabled={busy || password.length === 0}
            onClick={() =>
              void withPassword(async (secret) => {
                const created = await createDeviceA(secret);
                onRecovery(created.recoveryKey);
                return created.status;
              })
            }
          >
            创建保险库
          </button>
        ) : null}
        {id === "b" && phase === "empty" ? (
          <button
            className="primary"
            type="button"
            disabled={busy || !peerReady || password.length === 0}
            onClick={() => void withPassword((secret) => provisionDeviceB(secret))}
          >
            写入同一份保险库头并解锁
          </button>
        ) : null}
        {phase === "locked" ? (
          <button
            className="primary"
            type="button"
            disabled={busy || password.length === 0}
            onClick={() => void withPassword((secret) => unlockDevice(id, secret))}
          >
            解锁
          </button>
        ) : null}
        {phase === "unlocked" ? (
          <button
            type="button"
            disabled={busy}
            onClick={() => void onRun(() => syncDevice(id, endpoint.trim()))}
          >
            同步这台设备
          </button>
        ) : null}
        {phase === "unlocked" ? (
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setLoginPassword("");
              setDraftPassword("");
              void onRun(() => lockDevice(id));
            }}
          >
            锁定
          </button>
        ) : null}
      </div>

      {phase === "empty" ? (
        <p className="empty">
          {id === "b"
            ? "设备 B 还是空库。设备 A 解锁后，用同一个主密码把密封保险库头写到这里。"
            : "设备 A 还没有保险库。创建后会显示保险库编号和设备编号。"}
        </p>
      ) : null}
      {phase === "locked" ? <p className="empty">保险库已在磁盘上。解锁后才能看条目。</p> : null}

      {phase === "unlocked" && device ? (
        <>
          <table>
            <caption>条目</caption>
            <thead>
              <tr>
                <th>标题</th>
                <th>类型</th>
                <th>版本</th>
                <th>编号</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {device.items.length === 0 ? (
                <tr>
                  <td className="empty" colSpan={5}>
                    还没有条目。写一条笔记，同步之前另一台设备看不到它。
                    还没有条目。写一条登录或笔记，同步之前另一台设备看不到它。
                  </td>
                </tr>
              ) : (
                device.items.map((item) => (
                  <ItemRow
                    key={item.itemId}
                    item={item}
                    selected={item.itemId === selected?.itemId}
                    onSelect={() => {
                      setSelectedId(item.itemId);
                      setDraftTitle(item.title);
                      setDraftNotes(item.notes);
                      setDraftUsername(item.username ?? "");
                      setDraftPassword(item.password ?? "");
                      setDraftSecret(item.totpSecret ?? "");
                    }}
                  />
                ))
              )}
            </tbody>
          </table>

          <form
            className="composer"
            onSubmit={(event) => {
              event.preventDefault();
              void onRun(async () => {
                const next =
                  newKind === "login"
                    ? await createLogin(id, title, username, loginPassword, notes)
                    : newKind === "totp"
                      ? await createTotp(id, title, secret, notes)
                      : await createNote(id, title, notes);
                setTitle("");
                setUsername("");
                setLoginPassword("");
                setSecret("");
                setNotes("");
                return next;
              });
            }}
          >
            <fieldset className="kind">
              <legend>新条目</legend>
              <label>
                <input
                  type="radio"
                  name={id + "-kind"}
                  checked={newKind === "login"}
                  onChange={() => setNewKind("login")}
                />
                登录
              </label>
              <label>
                <input
                  type="radio"
                  name={id + "-kind"}
                  checked={newKind === "note"}
                  onChange={() => setNewKind("note")}
                />
                笔记
              </label>
              <label>
                <input
                  type="radio"
                  name={id + "-kind"}
                  checked={newKind === "totp"}
                  onChange={() => setNewKind("totp")}
                />
                验证码
              </label>
            </fieldset>
            <label>
              标题
              <input value={title} onChange={(event) => setTitle(event.target.value)} />
            </label>
            {newKind === "login" ? (
              <>
                <label>
                  用户名
                  <input value={username} autoComplete="off" onChange={(event) => setUsername(event.target.value)} />
                </label>
                <label>
                  密码
                  <input
                    type="password"
                    value={loginPassword}
                    autoComplete="new-password"
                    onChange={(event) => setLoginPassword(event.target.value)}
                  />
                </label>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    void onRun(async () => {
                      const generated = await generatePassword(Number(length) || 24);
                      setLoginPassword(generated);
                      return hostStatus();
                    })
                  }
                >
                  生成 {length} 位密码
                </button>
                <label>
                  长度
                  <input
                    inputMode="numeric"
                    value={length}
                    onChange={(event) => setLength(event.target.value)}
                  />
                </label>
              </>
            ) : null}
            {newKind === "totp" ? (
              <label>
                密钥
                <textarea
                  value={secret}
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(event) => setSecret(event.target.value)}
                />
              </label>
            ) : null}
            <label>
              备注
              <textarea value={notes} onChange={(event) => setNotes(event.target.value)} />
            </label>
            <button className="primary" type="submit" disabled={busy || title.trim().length === 0}>
              {newKind === "login" ? "新建登录" : newKind === "totp" ? "新建验证码" : "新建笔记"}
            </button>
          </form>

          <form
            className="composer"
            onSubmit={(event) => {
              event.preventDefault();
              if (!selected) {
                return;
              }
              const itemId = selected.itemId;
              const login = selected.kind === "登录";
              const totp = selected.kind === "验证码";
              void onRun(() =>
                totp
                  ? updateTotp(id, itemId, draftTitle, draftSecret, draftNotes)
                  : login
                    ? updateLogin(id, itemId, draftTitle, draftUsername, draftPassword, draftNotes)
                    : updateNote(id, itemId, draftTitle, draftNotes),
              );
            }}
          >
            <label>
              选中条目
              <input
                value={draftTitle}
                disabled={!selected}
                onChange={(event) => setDraftTitle(event.target.value)}
              />
            </label>
            {selected?.kind === "登录" ? (
              <>
                <label>
                  用户名
                  <input
                    value={draftUsername}
                    autoComplete="off"
                    disabled={!selected}
                    onChange={(event) => setDraftUsername(event.target.value)}
                  />
                </label>
                <label>
                  密码
                  <input
                    type="password"
                    value={draftPassword}
                    autoComplete="off"
                    disabled={!selected}
                    onChange={(event) => setDraftPassword(event.target.value)}
                  />
                </label>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    void onRun(async () => {
                      const generated = await generatePassword(Number(length) || 24);
                      setDraftPassword(generated);
                      return hostStatus();
                    })
                  }
                >
                  生成 {length} 位密码
                </button>
              </>
            ) : null}
            {selected?.kind === "验证码" ? (
              <label>
                密钥
                <textarea
                  value={draftSecret}
                  spellCheck={false}
                  autoComplete="off"
                  disabled={!selected}
                  onChange={(event) => setDraftSecret(event.target.value)}
                />
              </label>
            ) : null}
            <label>
              备注
              <textarea
                value={draftNotes}
                disabled={!selected}
                onChange={(event) => setDraftNotes(event.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || !selected || draftTitle.trim().length === 0}>
              保存修改
            </button>
          </form>
        </>
      ) : null}
    </section>
  );
}

function ItemRow({
  item,
  selected,
  onSelect,
}: {
  item: ItemView;
  selected: boolean;
  onSelect: () => void;
}) {
  const className = [item.conflictCopy ? "conflict" : "", selected ? "selected" : ""]
    .filter(Boolean)
    .join(" ");
  return (
    <tr className={className}>
      <td>
        <div>{item.deleted ? "已删除 " + item.title : item.title}</div>
        {item.totpCode ? (
          <div className="otp">
            {item.totpCode}
            <span> {item.totpRemaining} 秒</span>
          </div>
        ) : null}
      </td>
      <td>{item.kind}</td>
      <td>{item.revision}</td>
      <td className="ids">{item.itemId}</td>
      <td>
        <button type="button" onClick={onSelect}>
          {selected ? "已选" : "选用"}
        </button>
      </td>
    </tr>
  );
}
