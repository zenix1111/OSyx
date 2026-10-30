// The release link always works, even if the API is unavailable or rate-limited.
fetch('https://api.github.com/repos/OSyxSoftware/OSyx/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
  .then(response => response.ok ? response.json() : Promise.reject())
  .then(release => {
    if (typeof release.tag_name === 'string' && /^v?[0-9]+(?:\.[0-9]+){1,3}$/.test(release.tag_name)) {
      document.getElementById('release-label').textContent = `LATEST RELEASE ${release.tag_name.toUpperCase()}`;
    }
  }).catch(() => {});
