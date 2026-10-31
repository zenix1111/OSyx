// The release link always works, even if the API is unavailable or rate-limited.
fetch('https://api.github.com/repos/OSyxSoftware/OSyx/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
  .then(response => response.ok ? response.json() : Promise.reject())
  .then(release => {
    if (typeof release.tag_name === 'string' && /^v?[0-9]+(?:\.[0-9]+){1,3}$/.test(release.tag_name)) {
      document.getElementById('release-label').textContent = `LATEST RELEASE ${release.tag_name.toUpperCase()}`;
    }
  }).catch(() => {});

// Win Parity: numbers from winparity.json (written by scripts/site-winparity.py
// from a scan of the sources); the section keeps its text if the file is missing.
fetch('winparity.json').then(r => r.ok ? r.json() : Promise.reject()).then(d => {
  const pct = v => (v === null || v === undefined) ? 'n/a' : v.toFixed(1) + '%';
  const card = (key, value, note) => `<div class="parity-card"><span class="parity-key">${key}</span><strong>${value}</strong><small>${note}</small></div>`;
  document.getElementById('parity-cards').innerHTML =
    card('x64 COVERAGE', pct(d.x64.coverage), `${d.x64.implemented + d.x64.partial} of ${d.x64.reference_exports} exports`) +
    card('x86 / WOW64', pct(d.x86.coverage), `${d.x86.implemented + d.x86.partial} of ${d.x86.reference_exports} exports`) +
    card('BEHAVIOUR (x64)', pct(d.x64.behaviour), `${d.tests.checks_ok} checks passed, ${d.tests.programs} test programs`) +
    card('STUBS', String(d.x64.stubs + d.x86.stubs), `${d.x64.unsupported + d.x86.unsupported} error-only, ${d.x64.unknown + d.x86.unknown} unknown`);
  const table = (title, a) => `<div class="parity-table"><h3>${title}</h3>` + a.dlls.map(x =>
    `<div class="parity-row"><span>${x.dll}</span><span class="parity-bar"><i style="width:${Math.min(100, x.coverage)}%"></i></span><span>${pct(x.coverage)}</span></div>`).join('') + '</div>';
  document.getElementById('parity-tables').innerHTML = table('LARGEST DLLS, x64', d.x64) + table('LARGEST DLLS, x86 / WOW64', d.x86);
  const note = document.getElementById('parity-note');
  note.insertAdjacentHTML('afterbegin', `Scanned ${d.generated.slice(0, 10)} at commit ${d.commit} against Windows ${d.windows}. `);
}).catch(() => {
  document.getElementById('parity-cards').textContent = 'Win Parity data could not be loaded. Please refresh the page and try again.';
});
