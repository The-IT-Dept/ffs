// Sets the colour theme before the first paint, so a dark page never flashes light. The choice is
// stored under localStorage "ffs-theme" as "light", "dark" or "system"; anything else means
// "system", which follows the operating system's preference.
(function () {
  var choice = 'system'
  try {
    var stored = window.localStorage.getItem('ffs-theme')
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      choice = stored
    }
  } catch (e) {
    choice = 'system'
  }
  var dark = choice === 'dark'
  if (choice === 'system' && typeof window.matchMedia === 'function') {
    dark = window.matchMedia('(prefers-color-scheme: dark)').matches
  }
  document.documentElement.classList.toggle('dark', dark)
})()
