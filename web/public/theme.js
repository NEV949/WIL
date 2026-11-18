/* Sets the theme before the first paint, so the page never flashes. */
(function applyTheme() {
  var theme = "light";
  try {
    var stored = window.localStorage.getItem("oracle-hcm.theme");
    if (stored === "light" || stored === "dark") {
      theme = stored;
    } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
      theme = "dark";
    }
  } catch (error) {
    theme = "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
