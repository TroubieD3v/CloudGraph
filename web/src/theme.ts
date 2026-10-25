import { useEffect, useState } from "react";

export type Theme = "dark" | "light";

const KEY = "cloudgraph-theme";

/** Dark is the default; an explicit choice is remembered in localStorage. */
export function storedTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function apply(theme: Theme) {
  document.documentElement.dataset.theme = theme;
}

/** Applied before React renders so the first paint already has the right colours. */
export function initTheme() {
  apply(storedTheme());
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  useEffect(() => {
    apply(theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* storage may be unavailable; the theme still applies for this session */
    }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}
