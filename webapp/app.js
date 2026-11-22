(() => {
  'use strict';

  const token = document.querySelector('meta[name="xamltech-token"]').content;
  const app = document.getElementById('app');
  const toastBox = document.getElementById('toast');
  let state = null;
  let mongo = null;
  let mongoCollection = '';
  let source = null;
  let pollTimer = null;
  let saveTimer = null;
  let toastTimer = null;
  let sessionId = localStorage.getItem('xamltech.session');

  if (!sessionId || !/^[A-Za-z0-9_-]{1,64}$/.test(sessionId)) {
    sessionId = makeId();
    localStorage.setItem('xamltech.session', sessionId);
  }

  function makeId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, '');
    return 's' + Date.now().toString(36) + Math.random().toString(36).slice(2, 12);
  }

  function esc(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[ch]);
  }

  function when(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return esc(value);
    return `<time datetime="${esc(value)}">${esc(date.toLocaleString())}</time>`;
  }

  function clock(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '--:--:--' : date.toLocaleTimeString();
  }

  function code(value) {
    return `<span class="mono">${esc(value)}</span>`;
  }

  function badge(value, kind) {
    const name = String(value || 'unknown');
    const cls = kind || name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return `<span class="badge ${esc(cls)}">${esc(name)}</span>`;
  }

  function metric(label, value, kind) {
    return `<div class="metric ${kind || ''}"><b>${esc(value === undefined || value === null ? '—' : value)}</b><span>${esc(label)}</span></div>`;
  }

  function pageHead(eyebrow, title, copy, actions) {
    return `<div class="page-head"><div><div class="eyebrow">${esc(eyebrow)}</div><h1>${esc(title)}</h1><p>${esc(copy)}</p></div><div class="actions">${actions || ''}</div></div>`;
  }

  function panel(title, meta, body) {
    return `<section class="panel"><div class="panel-head"><h2>${esc(title)}</h2>${meta ? `<span class="mono">${esc(meta)}</span>` : ''}</div>${body}</section>`;
  }

  function table(headers, rows) {
    if (!rows.length) return '<div class="empty"><b>Nothing here yet</b><span>Run a scan or create a project to populate this view.</span></div>';
    return `<div class="table-wrap"><table><thead><tr>${headers.map((item) => `<th>${esc(item)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
  }

  function empty(title, copy) {
    return `<div class="empty"><b>${esc(title)}</b><span>${esc(copy)}</span></div>`;
  }

  function toast(message, error) {
    clearTimeout(toastTimer);
    toastBox.textContent = message;
    toastBox.className = 'toast show' + (error ? ' error' : '');
    toastTimer = setTimeout(() => { toastBox.className = 'toast'; }, 3500);
  }

  async function api(path, options) {
    const opts = Object.assign({ method: 'GET', headers: {} }, options || {});
    const headers = new Headers(opts.headers || {});
    if (opts.json !== undefined) {
      headers.set('Content-Type', 'application/json');
      headers.set('X-XamlTech-Token', token);
      opts.body = JSON.stringify(opts.json);
      delete opts.json;
    }
    opts.headers = headers;
    const response = await fetch(path, opts);
    const text = await response.text();
    let payload;
    try { payload = JSON.parse(text); } catch (_) { payload = text; }
    if (!response.ok) {
      const message = payload && payload.error ? payload.error : `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload;
  }

  function routeFromLocation() {
    const raw = location.pathname.replace(/\/+$/, '') || '/';
    if (raw === '/') return { name: 'reports', path: '/reports', key: 'reports' };
    const simple = raw.slice(1);
    if (['activity', 'reports', 'timeline', 'warnings', 'projects', 'mongo'].includes(simple)) {
      return { name: simple, path: raw, key: simple };
    }
    let match = raw.match(/^\/report\/([^/]+)$/);
    if (match) return { name: 'report', path: raw, key: 'reports', value: decodeURIComponent(match[1]) };
    match = raw.match(/^\/project\/([^/]+)$/);
    if (match) return { name: 'project', path: raw, key: 'projects', value: decodeURIComponent(match[1]) };
    return { name: 'notfound', path: raw, key: '' };
  }

  function navigate(path) {
    history.pushState({}, '', path);
    render();
  }

  async function registerSession() {
    const route = location.pathname + location.search;
    await api('/api/session', { method: 'POST', json: { id: sessionId, route: route } });
  }

  async function refresh(options) {
    const silent = Boolean(options && options.silent);
    try {
      state = await api('/api/state');
      if (!state.session) state.session = sessionId;
      document.getElementById('last-update').textContent = clock(Date.now());
      const sessions = state.activity && state.activity.sessions ? state.activity.sessions.length : 0;
      document.getElementById('session-count').textContent = `${sessions} session${sessions === 1 ? '' : 's'}`;
      if (!silent) render();
      else render(true);
    } catch (error) {
      if (!silent) toast(`Cannot load workspace: ${error.message}`, true);
      else document.getElementById('live-text').textContent = 'offline';
    }
  }

  function render(silent) {
    const route = routeFromLocation();
    const fullPath = location.pathname + location.search;
    document.querySelectorAll('[data-nav]').forEach((link) => {
      link.classList.toggle('active', link.dataset.nav === route.key);
    });
    document.getElementById('session-id').textContent = sessionId.slice(0, 12);
    document.getElementById('session-route').textContent = fullPath;
    if (!state) return;
    const focused = app.contains(document.activeElement) && ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);
    if (silent && focused) return;
    const views = {
      activity: renderActivity,
      reports: renderReports,
      report: () => renderReport(route.value),
      timeline: renderTimeline,
      warnings: renderWarnings,
      projects: renderProjects,
      project: () => renderProject(route.value),
      mongo: renderMongo,
      notfound: renderNotFound
    };
    app.innerHTML = (views[route.name] || renderNotFound)();
    registerSession().catch(() => {});
  }

  function renderActivity() {
    const activity = state.activity || {};
    const processes = activity.processes || [];
    const tools = processes.filter((item) => item.kind !== 'web');
    const runs = activity.active_runs || [];
    const sessions = activity.sessions || [];
    const events = activity.events || [];
    const processRows = tools.map((item) => `<tr><td>${code(item.pid)}</td><td>${badge(item.kind)}</td><td>${when(item.started)}</td><td class="mono">${esc(item.command)}</td></tr>`);
    const runRows = runs.map((item) => `<tr><td>${code(item.name)}</td><td>${when(item.modified)}</td><td>${badge(item.status, 'warn')}</td><td class="mono">${esc(item.detail)}</td></tr>`);
    const sessionRows = sessions.map((item) => `<div class="session-row"><span class="mono">${esc(item.id.slice(0, 12))}</span><span class="muted">${esc(item.route)}</span><span>${badge(item.age, item.age === 'now' ? 'ok' : 'muted')}</span></div>`);
    const eventRows = events.slice(0, 30).map((item) => `<div class="event"><time>${esc(clock(item.at))}</time><span>${esc(item.message)}</span></div>`);
    return pageHead('Live / 01', 'Runtime activity', 'Running toolkit processes, active runs, browser sessions and recent workspace changes.', '')
      + `<div class="metrics">${metric('Running tools', tools.length, tools.length ? 'warn' : 'good')}${metric('Incomplete runs', runs.length)}${metric('Live sessions', sessions.length)}${metric('Recent events', events.length)}</div>`
      + panel('Running tools', `${tools.length} detected`, table(['PID', 'Kind', 'Started', 'Command'], processRows))
      + `<div class="grid two">`
      + panel('Active sessions', `${sessions.length} clients`, sessionRows.join('') || empty('No active sessions', 'Open another browser to see it appear here.'))
      + panel('Recent changes', 'workspace events', `<div class="event-list">${eventRows.join('') || empty('No recent changes', 'Scan output and project edits will appear here.')}</div>`)
      + `</div>`
      + panel('Incomplete runs', 'awaiting report', table(['Run', 'Modified', 'Status', 'Detail'], runRows));
  }

  function assignForm(run, projects, compact) {
    const options = projects.map((item) => `<option value="${esc(item.name)}">${esc(item.name)}</option>`).join('');
    return `<form class="inline-form" data-form="assign">`
      + `<div class="field"><label for="assign-project">Project</label><select id="assign-project" name="project" required><option value="">Choose project…</option>${options}</select></div>`
      + `<div class="field"><label for="assign-run">Run</label><input id="assign-run" name="run" value="${esc(run)}" required></div>`
      + `${compact ? '' : '<div class="field"><label for="assign-step">Step id (optional)</label><input id="assign-step" name="step" placeholder="discover"></div>'}`
      + `<button class="btn primary" type="submit">Assign report</button></form>`;
  }

  function renderReports() {
    const scans = state.reports || [];
    const projects = state.projects || [];
    const warnings = state.warnings || [];
    const rows = scans.map((item) => `<tr><td>${code(item.name)}</td><td>${when(item.generated)}</td><td>${esc(item.profile)}</td><td>${esc(item.targets)}</td><td class="right mono">${esc(item.hosts_up)}/${esc(item.hosts_total)}</td><td class="right mono">${esc(item.ports)}</td><td>${badge(item.warnings, item.warnings ? 'warn' : 'ok')}</td><td class="nowrap"><a class="ghost" href="/report/${encodeURIComponent(item.name)}" data-link>Open</a> <button class="ghost" type="button" data-assign-run="${esc(item.name)}">Assign</button></td></tr>`);
    return pageHead('Reports / 02', 'Scan reports', 'Every completed run under the configured output directory, newest first.', `<a class="btn" href="/run/${encodeURIComponent(scans[0] ? scans[0].name : 'latest')}/service.html" target="_blank" rel="noopener">Latest service page</a>`)
      + `<div class="metrics">${metric('Reports', scans.length)}${metric('Warnings', warnings.length, warnings.length ? 'warn' : 'good')}${metric('Hosts up', scans.reduce((sum, item) => sum + Number(item.hosts_up || 0), 0))}${metric('Open ports', scans.reduce((sum, item) => sum + Number(item.ports || 0), 0))}</div>`
      + panel('Assign a run to a project', 'writes project JSON', assignForm('', projects, true))
      + panel('Completed runs', `${scans.length} reports`, table(['Run', 'Generated', 'Profile', 'Targets', 'Hosts', 'Ports', 'Warnings', 'Actions'], rows));
  }

  function renderReport(name) {
    const scan = (state.reports || []).find((item) => item.name === name);
    if (!scan) return renderNotFound();
    const warnings = (state.warnings || []).filter((item) => item.run === name);
    const projects = state.projects || [];
    const rows = warnings.map((item) => `<tr><td>${badge(item.severity)}</td><td>${code(item.host)}</td><td>${code(item.port)}</td><td>${esc(item.title)}</td><td class="muted">${esc(item.detail)}</td><td>${esc(item.rule)}</td></tr>`);
    return pageHead('Reports / 02', scan.name, `${scan.profile} · ${scan.targets || 'no targets recorded'}`, `<a class="btn primary" href="/run/${encodeURIComponent(name)}/service.html" target="_blank" rel="noopener">Open service page</a><a class="btn" href="/run/${encodeURIComponent(name)}/report.html" target="_blank" rel="noopener">Full report</a>`)
      + `<div class="metrics">${metric('Generated', scan.generated ? new Date(scan.generated).toLocaleString() : '—')}${metric('Hosts up', `${scan.hosts_up}/${scan.hosts_total}`)}${metric('Open ports', scan.ports)}${metric('Warnings', warnings.length, warnings.length ? 'warn' : 'good')}</div>`
      + panel('Assign to project', 'writes project JSON', assignForm(scan.name, projects, false))
      + panel('Findings', `${warnings.length} items`, table(['Severity', 'Host', 'Port', 'Finding', 'Detail', 'Rule'], rows));
  }

  function renderTimeline() {
    const rows = (state.timeline || []).map((item) => `<div class="timeline-item ${item.status && item.status.includes('fail') ? 'crit' : item.status && item.status.indexOf('warning') > 0 ? 'warn' : ''}"><time>${esc(item.time || 'unknown time')}</time><h3>${esc(item.event)} · ${esc(item.label)}</h3><p>${esc(item.detail)} ${item.run ? `· ${esc(item.run)}` : ''} ${item.project ? `· ${esc(item.project)}` : ''} ${item.status ? `· ${esc(item.status)}` : ''}</p></div>`);
    const activity = state.activity || {};
    const events = (activity.events || []).slice(0, 12).map((item) => `<div class="event"><time>${esc(clock(item.at))}</time><span>${esc(item.message)}</span></div>`);
    return pageHead('Timeline / 03', 'Scan timeline', 'Scan runs and project activity merged into one ordered history.', `<a class="btn" href="/activity" data-link>Live activity</a>`)
      + panel('History', `${rows.length} entries`, `<div class="timeline-list">${rows.join('') || empty('No history yet', 'Completed scans appear here automatically.')}</div>`)
      + panel('Workspace events', 'recent', `<div class="event-list">${events.join('') || empty('No events yet', 'Project edits and assignments appear here.')}</div>`);
  }

  function renderWarnings() {
    const query = new URLSearchParams(location.search);
    const selected = (query.get('sev') || 'ALL').toUpperCase();
    const levels = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const actions = levels.map((level) => `<a class="ghost ${selected === level ? 'active' : ''}" href="/warnings?sev=${level}" data-link>${level}</a>`).join('');
    const warnings = (state.warnings || []).filter((item) => selected === 'ALL' || item.severity === selected);
    const rows = warnings.map((item) => `<tr><td>${badge(item.severity)}</td><td>${code(item.run)}</td><td>${code(item.host)}</td><td>${code(item.port)}</td><td>${esc(item.title)}</td><td class="muted">${esc(item.detail)}</td><td class="muted">${esc(item.advice)}</td></tr>`);
    return pageHead('Warnings / 04', 'Security warnings', 'Heuristic findings from completed reports. Verify each item before acting on it.', actions)
      + `<div class="metrics">${levels.slice(1).map((level) => metric(level, (state.warnings || []).filter((item) => item.severity === level).length, level === 'CRITICAL' || level === 'HIGH' ? 'hot' : '')).join('')}</div>`
      + panel(selected === 'ALL' ? 'All findings' : `${selected} findings`, `${warnings.length} items`, table(['Severity', 'Run', 'Host', 'Port', 'Finding', 'Detail', 'Advice'], rows));
  }

  function renderProjects() {
    const projects = state.projects || [];
    const rows = projects.map((item) => {
      const counts = item.counts || {};
      const next = item.next_action || {};
      return `<tr><td><a href="/project/${encodeURIComponent(item.name)}" data-link>${esc(item.name)}</a></td><td>${badge(item.status, item.status === 'done' ? 'done' : item.status === 'failed' ? 'crit' : 'warn')}</td><td>${esc(item.info)}</td><td class="mono">${esc(next.step || '—')} ${esc(next.goal || '')}</td><td class="right mono">${esc(counts.done || 0)}/${esc((item.plan || []).length)}</td><td class="right mono">${esc((item.timeline || []).length)}</td></tr>`;
    });
    const form = `<form class="inline-form" data-form="create-project"><div class="field"><label for="new-name">Project name</label><input id="new-name" name="name" required></div><div class="field"><label for="new-info">Info</label><input id="new-info" name="info" placeholder="engagement / owner / scope"></div><div class="field"><label for="new-goals">Goals (comma separated)</label><input id="new-goals" name="goals" placeholder="enumerate hosts, review exposure"></div><button class="btn primary" type="submit">Create project</button></form>`;
    return pageHead('Projects / 05', 'Assessment projects', 'Projects live as JSON files and can be edited directly in this workspace.', '')
      + `<div class="metrics">${metric('Projects', projects.length)}${metric('Steps done', projects.reduce((sum, item) => sum + Number((item.counts || {}).done || 0), 0), 'good')}${metric('Scans assigned', projects.reduce((sum, item) => sum + (item.timeline || []).length, 0))}${metric('Needs action', projects.filter((item) => item.status === 'needs-action' || item.status === 'failed').length, 'warn')}</div>`
      + panel('New project', 'writes project JSON', form)
      + panel('All projects', `${projects.length} records`, table(['Project', 'Status', 'Info', 'Next action', 'Steps', 'Scans'], rows));
  }

  function renderProject(name) {
    const project = (state.projects || []).find((item) => item.name === name);
    if (!project) return renderNotFound();
    const statuses = state.statuses || ['todo', 'done', 'failed', 'needs-action'];
    const steps = (project.plan || []).map((step) => `<div class="grid three"><div class="field"><label>Step ${esc(step.order)} · ${esc(step.id)}</label><input name="step_goal_${esc(step.id)}" value="${esc(step.goal)}" data-autosave></div><div class="field"><label>Status</label><select name="step_status_${esc(step.id)}" data-autosave>${statuses.map((status) => `<option value="${esc(status)}" ${status === step.status ? 'selected' : ''}>${esc(status)}</option>`).join('')}</select></div><div class="field"><label>Note</label><input name="step_note_${esc(step.id)}" value="${esc(step.note)}" data-autosave></div></div>`).join('');
    const form = `<form data-autosave-form data-project="${esc(project.name)}"><div class="grid two"><div class="field"><label for="project-info">Info</label><input id="project-info" name="info" value="${esc(project.info)}" data-autosave></div><div class="field"><label for="project-goals">Goals</label><textarea id="project-goals" name="goals" data-autosave>${esc((project.goals || []).join('\n'))}</textarea></div></div>${steps ? `<h3>Plan</h3><div class="grid">${steps}</div>` : ''}<div class="save-state" data-save-state role="status" aria-live="polite">Edits save automatically.</div></form>`;
    const addStep = `<form class="inline-form" data-form="add-step" data-project="${esc(project.name)}"><div class="field"><label for="step-id">Step id</label><input id="step-id" name="step" placeholder="report" required></div><div class="field"><label for="step-goal">Goal</label><input id="step-goal" name="goal" placeholder="write final report"></div><button class="btn" type="submit">Add step</button></form>`;
    const scans = (project.timeline || []).map((item) => `<tr><td>${when(item.started)}</td><td>${esc(item.profile)}</td><td>${badge(item.status, item.status === 'done' ? 'done' : 'warn')}</td><td>${esc(item.targets)}</td><td>${code(PathName(item.run))}</td><td>${code(item.step || '—')}</td></tr>`);
    const counts = project.counts || {};
    const next = project.next_action || {};
    return pageHead('Projects / 05', project.name, project.info || 'No project info recorded.', `<a class="btn" href="/projects" data-link>All projects</a>`)
      + `<div class="metrics">${metric('Status', project.status)}${metric('Steps done', `${counts.done || 0}/${(project.plan || []).length}`)}${metric('Scans', (project.timeline || []).length)}${metric('Next', next.step || '—')}</div>`
      + panel('Edit project', 'autosaves to JSON', form + '<div class="panel-body">' + addStep + '</div>')
      + panel('Assigned scans', `${(project.timeline || []).length} runs`, table(['Started', 'Profile', 'Status', 'Targets', 'Run', 'Step'], scans));
  }

  function PathName(value) {
    return String(value || '').split('/').pop();
  }

  function renderMongo() {
    const data = mongo || state.mongo || {};
    const collections = data.collections || [];
    if (!collections.some((item) => item.name === mongoCollection)) mongoCollection = collections[0] ? collections[0].name : '';
    const active = collections.find((item) => item.name === mongoCollection);
    const buttons = collections.map((item) => `<button type="button" data-collection="${esc(item.name)}" class="${item.name === mongoCollection ? 'active' : ''}"><span>${esc(item.name)}</span><small>${esc(item.count)}</small></button>`).join('');
    const docs = active ? (active.documents || []) : [];
    const body = docs.map((item, index) => {
      const identity = item._id || item.id || item.name || `doc ${index + 1}`;
      return `<div class="doc"><div class="doc-head"><b>${esc(identity)}</b><span class="muted">${esc(index + 1)} of ${esc(docs.length)}</span></div><pre class="code">${esc(JSON.stringify(item, null, 2))}</pre></div>`;
    }).join('');
    const sourceName = data.source === 'mongosh' ? 'live mongosh' : 'bundled fixture';
    return pageHead('MongoDB / 06', 'NoSQL sample data', 'Inspect sample collections from a local MongoDB instance or the bundled JSON fallback.', badge(sourceName, data.source === 'mongosh' ? 'ok' : 'warn'))
      + `<div class="metrics">${metric('Source', sourceName)}${metric('Database', data.database || '—')}${metric('Collections', collections.length)}${metric('Documents shown', docs.length)}</div>`
      + panel('Collections', `${collections.length} available`, `<div class="mongo-layout"><div class="collection-list">${buttons || empty('No collections', 'Add sample data under config/mongo.')}</div><div>${body || empty('No documents', 'Select a collection to inspect its documents.')}</div></div>`);
  }

  function renderNotFound() {
    return pageHead('Workspace', 'Not found', 'That route is not part of this workspace.', `<a class="btn primary" href="/reports" data-link>Go to reports</a>`)
      + panel('Unknown route', esc(location.pathname), empty('Nothing at this address', 'Use the sidebar to continue.'));
  }

  async function saveProjectForm(form) {
    const name = form.dataset.project;
    const data = {};
    new FormData(form).forEach((value, key) => { data[key] = value; });
    const status = form.querySelector('[data-save-state]');
    try {
      const result = await api(`/api/projects/${encodeURIComponent(name)}`, { method: 'POST', json: data });
      if (status) {
        status.textContent = `Saved ${clock(Date.now())}`;
        status.className = 'save-state saved';
      }
      await refresh({ silent: true });
      return result;
    } catch (error) {
      if (status) {
        status.textContent = error.message;
        status.className = 'save-state error';
      }
      throw error;
    }
  }

  async function handleSubmit(event) {
    const form = event.target;
    event.preventDefault();
    try {
      if (form.hasAttribute('data-autosave-form')) {
        clearTimeout(saveTimer);
        await saveProjectForm(form);
      } else if (form.dataset.form === 'assign') {
        const data = Object.fromEntries(new FormData(form));
        const result = await api('/api/projects/assign', { method: 'POST', json: data });
        if (result.already) toast('That run is already assigned.');
        else toast(`Assigned ${data.run} to ${data.project}.`);
        await refresh();
      } else if (form.dataset.form === 'create-project') {
        const data = Object.fromEntries(new FormData(form));
        const result = await api('/api/projects', { method: 'POST', json: data });
        toast(`Created ${result.name}.`);
        navigate(`/project/${encodeURIComponent(result.name)}`);
      } else if (form.dataset.form === 'add-step') {
        const data = Object.fromEntries(new FormData(form));
        await api(`/api/projects/${encodeURIComponent(form.dataset.project)}/step`, { method: 'POST', json: data });
        toast(`Added step ${data.step}.`);
        await refresh();
      }
    } catch (error) {
      toast(error.message, true);
    }
  }

  function handleInput(event) {
    const target = event.target;
    if (!target.hasAttribute('data-autosave')) return;
    const form = target.closest('form[data-autosave-form]');
    if (!form) return;
    const status = form.querySelector('[data-save-state]');
    clearTimeout(saveTimer);
    if (status) {
      status.textContent = 'saving…';
      status.className = 'save-state';
    }
    saveTimer = setTimeout(() => {
      saveProjectForm(form).catch((error) => toast(error.message, true));
    }, 450);
  }

  function handleClick(event) {
    const link = event.target.closest('a[data-link]');
    if (link && !event.metaKey && !event.ctrlKey && !event.shiftKey && link.target !== '_blank') {
      event.preventDefault();
      navigate(link.getAttribute('href'));
      return;
    }
    const assign = event.target.closest('[data-assign-run]');
    if (assign) {
      const input = app.querySelector('input[name="run"]');
      const select = app.querySelector('select[name="project"]');
      if (input) {
        input.value = assign.dataset.assignRun;
        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
      if (select) select.focus();
      return;
    }
    const collection = event.target.closest('[data-collection]');
    if (collection) {
      mongoCollection = collection.dataset.collection;
      render();
    }
  }

  async function loadMongo() {
    try {
      mongo = await api('/api/mongo');
      mongoCollection = '';
      render();
    } catch (error) {
      toast(`MongoDB viewer unavailable: ${error.message}`, true);
    }
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(() => refresh({ silent: true }), 3500);
  }

  function stopPolling() {
    clearInterval(pollTimer);
    pollTimer = null;
  }

  function connectLive() {
    if (typeof EventSource !== 'function') {
      document.getElementById('live-text').textContent = 'polling';
      startPolling();
      return;
    }
    source = new EventSource('/api/events');
    source.onopen = () => {
      document.getElementById('live-text').textContent = 'live';
      document.getElementById('live-pulse').classList.add('on');
      stopPolling();
    };
    source.onerror = () => {
      document.getElementById('live-text').textContent = 'reconnecting';
      document.getElementById('live-pulse').classList.remove('on');
      startPolling();
    };
    source.addEventListener('state', (event) => {
      let reason = 'workspace changed';
      try { reason = JSON.parse(event.data).reason || reason; } catch (_) {}
      document.getElementById('live-text').textContent = reason;
      refresh({ silent: true });
    });
  }

  document.addEventListener('click', handleClick);
  document.getElementById('refresh').addEventListener('click', () => refresh());
  app.addEventListener('submit', handleSubmit);
  app.addEventListener('input', handleInput);
  app.addEventListener('change', handleInput);
  window.addEventListener('popstate', render);
  window.addEventListener('beforeunload', () => {
    if (source) source.close();
  });
  document.getElementById('version').textContent = '2.5.0';

  if (location.pathname === '/') history.replaceState({}, '', '/reports');
  refresh().then(loadMongo);
  connectLive();
  setInterval(() => registerSession().catch(() => {}), 20000);
})();
