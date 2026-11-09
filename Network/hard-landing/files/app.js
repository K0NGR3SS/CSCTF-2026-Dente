const pinForm = document.querySelector('#pin-form');
const pinStatus = document.querySelector('#pin-status');
const sessionStatus = document.querySelector('#session-status');
const station = document.querySelector('#station');
const bootstrapView = document.querySelector('#bootstrap');
const channelStatus = document.querySelector('#channel-status');
const positionStatus = document.querySelector('#position-status');
const roomStatus = document.querySelector('#room-status');
let stationData = null, channel = null, nextSequence = 1, idleDeadline = 0;

function entry(key, value) {
  const term = document.createElement('dt'); term.textContent = key;
  const detail = document.createElement('dd'); detail.textContent = String(value);
  bootstrapView.append(term, detail);
}
function mapFor(data) {
  const box = document.querySelector('#map');
  box.setAttribute('aria-label', `Cordon Seven map: target centre ${data.lat_e6 / 1e6}, ${data.lon_e6 / 1e6}; radius ${data.radius_m} metres; station starts outside`);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 600 180');
  const circle = document.createElementNS(svg.namespaceURI, 'circle');
  for (const [k,v] of Object.entries({cx:390,cy:90,r:46,fill:'#20604f',stroke:'#88dac8','stroke-width':2})) circle.setAttribute(k,v);
  const dot = document.createElementNS(svg.namespaceURI, 'circle');
  for (const [k,v] of Object.entries({cx:120,cy:90,r:7,fill:'#f7c76d'})) dot.setAttribute(k,v);
  const label = document.createElementNS(svg.namespaceURI, 'text'); label.setAttribute('x','320'); label.setAttribute('y','155'); label.textContent='Cordon Seven';
  const outside = document.createElementNS(svg.namespaceURI, 'text'); outside.setAttribute('x','75'); outside.setAttribute('y','155'); outside.textContent='Station report';
  svg.append(circle,dot,label,outside); box.replaceChildren(svg);
}
function send(data) { if (channel?.readyState === WebSocket.OPEN) channel.send(JSON.stringify(data)); }
function reportOutside() {
  if (!stationData || channel?.readyState !== WebSocket.OPEN) return;
  send({type:'position.update',sequence:nextSequence++,observed_at_ms:Date.now(),latitude:-47.200610,longitude:-126.302400,accuracy_m:18.0});
}
function connect() {
  channel = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`);
  nextSequence = 1;
  channelStatus.textContent = 'Connecting to the station channel…';
  channel.addEventListener('open', () => {
    send({type:'station.authenticate',sequence:nextSequence++,cap:stationData.cap});
  });
  channel.addEventListener('message', event => {
    let message;
    try { message = JSON.parse(event.data); } catch { channelStatus.textContent = 'Unreadable channel response.'; return; }
    if (Number.isInteger(message.next_sequence)) nextSequence = message.next_sequence;
    if (message.type === 'station.accepted') {
      channelStatus.textContent = `Connected. Position freshness ${message.freshness_ms / 1000}s; eligibility ${message.eligibility_ttl_ms / 1000}s; allowance ${message.limit} frames / ${message.window_ms / 1000}s. Next sequence ${message.next_sequence}.`;
      reportOutside();
    } else if (message.type === 'position.accepted') {
      positionStatus.textContent = `Position ${message.inside ? 'inside' : 'outside'}; distance ${message.distance_m} m; room ${message.eligible_room ?? 'none'}; eligibility expires ${message.eligibility_expires_ms ? new Date(message.eligibility_expires_ms).toLocaleTimeString() : 'none'}. Next sequence ${message.next_sequence}.`;
    } else if (message.type === 'error') {
      roomStatus.textContent = `Channel error ${message.code}; next sequence ${message.next_sequence}.`;
    } else if (message.type === 'room.snapshot') {
      roomStatus.textContent = `${message.classification}: ${message.briefing} ${message.clearance_token}`;
    }
  });
  channel.addEventListener('close', event => { channelStatus.textContent = `Channel closed (${event.code}). Reload to reconnect.`; });
  channel.addEventListener('error', () => { channelStatus.textContent = 'Channel error. Reload to reconnect.'; });
}

pinForm.addEventListener('submit', async event => {
  event.preventDefault();
  pinStatus.textContent = 'Checking PIN…';
  try {
    const pin = document.querySelector('#pin').value;
    const response = await fetch('/api/station/pin-check', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});
    const result = await response.json();
    if (!response.ok) { pinStatus.textContent = `Check failed: ${result.code}.`; return; }
    // Deliberately wrong trust boundary: the browser's local branch decides whether to activate.
    const attempt = result.attempt;
    if (!result.success) { pinStatus.textContent = `PIN rejected (${result.code}). Attempt ${attempt} expires in ${result.expires_in_ms / 1000}s.`; return; }
    const activation = await fetch('/api/station/activate', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({attempt})});
    const data = await activation.json();
    if (!activation.ok) { pinStatus.textContent = `Activation failed: ${data.code}.`; return; }
    stationData = data; station.hidden = false;
    pinStatus.textContent = 'Station activated.';
    entry('Capability', data.cap); entry('Room', data.room);
    entry('Target centre', `${data.lat_e6 / 1e6}, ${data.lon_e6 / 1e6}`);
    entry('Radius', `${data.radius_m} m`);
    entry('Synthetic station position', '-47.200610, -126.302400');
    entry('Server time', new Date(data.server_time_ms).toLocaleString());
    mapFor(data); connect();
  } catch { pinStatus.textContent = 'Station request failed. Try again.'; }
});

async function refreshSession() {
  try {
    const response = await fetch('/api/station/session', {cache:'no-store'});
    const data = await response.json();
    if (!response.ok || !data.active) { sessionStatus.textContent = 'Station session expired. Reload this page.'; return; }
    idleDeadline = Date.now() + data.session_idle_expires_in_ms;
  } catch { sessionStatus.textContent = 'Session check unavailable; retrying.'; }
}
function showIdle() {
  if (idleDeadline) sessionStatus.textContent = `Station session idle expiry in about ${Math.max(0,Math.ceil((idleDeadline-Date.now())/60000))} minutes. The launcher runs its own instance timer.`;
}
refreshSession(); setInterval(refreshSession, 300000); setInterval(showIdle, 30000); showIdle();
