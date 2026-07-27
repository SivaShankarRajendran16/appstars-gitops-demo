import React, { useState, useEffect, useRef } from 'react';
import './App.css';

function truncateAddr(addr) {
  if (!addr) return '';
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [attempts, setAttempts] = useState(1);
  const [message, setMessage] = useState('');
  const [aiStatus, setAiStatus] = useState('');
  const [txHash, setTxHash] = useState('');
  const [blockNumber, setBlockNumber] = useState(null);
  const [chainStatus, setChainStatus] = useState(null);
  const [auditTrail, setAuditTrail] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [newBlockIndex, setNewBlockIndex] = useState(null);
  const [blockTick, setBlockTick] = useState(false);
  const prevBlock = useRef(null);

  const fetchChainStatus = async () => {
    try {
      const res = await fetch('/api/chain-status');
      const data = await res.json();
      if (prevBlock.current !== null && data.current_block !== prevBlock.current) {
        setBlockTick(true);
        setTimeout(() => setBlockTick(false), 600);
      }
      prevBlock.current = data.current_block;
      setChainStatus(data);
    } catch {
      setChainStatus(null);
    }
  };

  const fetchAuditTrail = async () => {
    try {
      const res = await fetch('/api/audit-trail');
      const data = await res.json();
      setAuditTrail(data.entries || []);
    } catch {
      setAuditTrail([]);
    }
  };

  useEffect(() => {
    fetchChainStatus();
    fetchAuditTrail();
    const interval = setInterval(fetchChainStatus, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setMessage(''); setAiStatus(''); setTxHash(''); setBlockNumber(null);
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, password_attempts: parseInt(attempts) })
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setAiStatus(data.ai_threat_assessment);
        setTxHash(data.blockchain_audit_tx);
        setBlockNumber(data.block_number);
      } else {
        setMessage(data.detail || 'Request rejected');
      }
      await fetchChainStatus();
      const before = auditTrail.length;
      await fetchAuditTrail();
      setNewBlockIndex(before);
      setTimeout(() => setNewBlockIndex(null), 1400);
    } catch (err) {
      setMessage('Could not reach the processing cluster.');
    } finally {
      setSubmitting(false);
    }
  };

  const isAnomalous = aiStatus === 'ANOMALOUS_ATTACK_WARNING';
  const isRejected = message && message.toLowerCase().includes('blocked');

  return (
    <div className="portal">
      <div className="portal__inner">
        <header className="portal__header">
          <p className="eyebrow">AI-DRIVEN WEB3 SECURITY GATEWAY</p>
          <h1 className="wordmark">Appstars Security Portal</h1>
        </header>

        <section className="console" aria-label="Live chain status">
          <div className="console__row">
            <span className={`dot ${chainStatus?.connected ? 'dot--live' : 'dot--dead'}`} />
            <span className="console__label">
              {chainStatus?.connected ? 'RPC node connected' : 'RPC node unreachable'}
            </span>
          </div>
          <div className="console__row console__row--data">
            <div className="console__stat">
              <span className="console__stat-label">Block height</span>
              <span className={`console__stat-value mono ${blockTick ? 'tick' : ''}`}>
                {chainStatus?.current_block ?? '—'}
              </span>
            </div>
            <div className="console__stat">
              <span className="console__stat-label">Contract</span>
              <span className="console__stat-value mono">
                {chainStatus?.contract_deployed ? truncateAddr(chainStatus.contract_address) : 'deploying…'}
              </span>
            </div>
          </div>
        </section>

        <section className="card">
          <form onSubmit={handleLogin}>
            <label className="field">
              <span>Username</span>
              <input type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" />
            </label>
            <label className="field">
              <span>Password</span>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="off" />
            </label>
            <label className="field">
              <span>Login attempts <em>(5+ triggers anomaly detection)</em></span>
              <input type="number" min="1" value={attempts} onChange={e => setAttempts(e.target.value)} />
            </label>
            <button type="submit" className="btn" disabled={submitting}>
              {submitting ? (
                <span className="btn__mining">
                  Signing on-chain<span className="dots"><i/><i/><i/></span>
                </span>
              ) : 'Verify and sign on-chain'}
            </button>
          </form>

          {message && (
            <div className={`result ${isRejected ? 'result--danger' : 'result--ok'}`}>
              <p className="result__msg">{message}</p>
              {aiStatus && (
                <span className={`pill ${isAnomalous ? 'pill--danger' : 'pill--ok'}`}>
                  {aiStatus.replaceAll('_', ' ')}
                </span>
              )}
              {txHash && (
                <div className="receipt mono">
                  <div><span className="receipt__label">tx</span>{txHash}</div>
                  <div><span className="receipt__label">block</span>{blockNumber}</div>
                </div>
              )}
            </div>
          )}
        </section>

        <section className="ledger">
          <h2 className="ledger__title">On-chain audit ledger <span className="mono">({auditTrail.length})</span></h2>
          <div className="chain">
            {auditTrail.slice().reverse().map((entry) => (
              <div
                key={entry.index}
                className={`block ${entry.index === newBlockIndex ? 'block--new' : ''}`}
              >
                <div className="block__connector" />
                <div className="block__body">
                  <span className="block__index mono">#{entry.index}</span>
                  <span className="block__user">{entry.username}</span>
                  <span className={`pill pill--small ${entry.status === 'SUCCESS' ? 'pill--ok' : 'pill--danger'}`}>
                    {entry.status}
                  </span>
                  <span className="block__time mono">
                    {new Date(entry.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
            {auditTrail.length === 0 && (
              <p className="ledger__empty">No blocks mined yet — sign in to write the first entry.</p>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

export default App;
