/**
 * CÍVIKA DESIGN SYSTEM — ANTI-FLASH HEAD INIT SCRIPT
 * Incrustar de forma síncrona en el <head> antes de renderizar cualquier elemento HTML.
 */
(function () {
  function getThemePreference() {
    var name = "casmarts_theme";
    var decodedCookie = decodeURIComponent(document.cookie);
    var match = decodedCookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return match ? match[2] : "system";
  }

  try {
    var theme = getThemePreference();
    var root = document.documentElement;
    if (theme === "dark") {
      root.setAttribute("data-theme", "dark");
    } else if (theme === "light") {
      root.setAttribute("data-theme", "light");
    } else {
      var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.setAttribute("data-theme", prefersDark ? "dark" : "light");
    }
  } catch (e) {
    console.error("CivikaThemeInit failed", e);
  }
})();
