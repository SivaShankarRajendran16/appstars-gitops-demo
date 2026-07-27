import React, { useState } from 'react';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [attempts, setAttempts] = useState(1);
  const [message, setMessage] = useState('');
  const [aiStatus, setAiStatus] = useState('');
  const [txHash, setTxHash] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setMessage(''); setAiStatus(''); setTxHash('');
    try {
      const response = await fetch('http://192.168.49', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, password_attempts: parseInt(attempts) })
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setAiStatus(data.ai_threat_assessment);
        setTxHash(data.blockchain_audit_tx);
      } else {
        setMessage(`Auth Flagged: ${data.detail}`);
      }
    } catch (err) {
      setMessage("Failed to reach processing cluster.");
    }
  };

  return (
    <div style={{ padding: '40px', fontFamily: 'sans-serif', maxWidth: '450px', margin: 'auto' }}>
      <h2>Appstars AI + Web3 Security Portal</h2>
      <form onSubmit={handleLogin}>
        <div style={{ marginBottom: '10px' }}>
          <label>Username:</label>
          <input type="text" value={username} onChange={e => setUsername(e.target.value)} style={{ width: '100%' }} />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Password:</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} style={{ width: '100%' }} />
        </div>
        <div style={{ marginBottom: '20px' }}>
          <label>Login Attempts (Set to 5+ to trigger ML Anomaly Detection):</label>
          <input type="number" value={attempts} onChange={e => setAttempts(e.target.value)} style={{ width: '100%' }} />
        </div>
        <button type="submit" style={{ padding: '10px 20px', backgroundColor: '#007bff', color: 'white', border: 'none', cursor: 'pointer' }}>
          Verify and Sign On-Chain
        </button>
      </form>
      {message && <p style={{ marginTop: '20px' }}><strong>Result:</strong> {message}</p>}
      {aiStatus && <p style={{ color: 'green' }}><strong>AI Threat Assessment:</strong> {aiStatus}</p>}
      {txHash && (
        <div style={{ wordBreak: 'break-all', fontSize: '11px', background: '#eee', padding: '10px', marginTop: '10px' }}>
          <strong>Immutable Blockchain Audit Log Receipt:</strong> <br/> {txHash}
        </div>
      )}
    </div>
  );
}
export default App;
