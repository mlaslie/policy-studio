// Code block with light syntax highlighting (shell, HCL, Python, JSON/YAML) and a Copy button.
// Adapted from the demo UI's CodeView.
import type { ReactNode } from "react";
import { CopyButton } from "./Glass";

export type Lang = "shell" | "hcl" | "python" | "json";

const KW: Record<Lang, RegExp> = {
  shell: /^(gcloud|curl|jq|cat|terraform|agents-cli|set|export|python3?|pip|EOF)$/,
  hcl: /^(resource|variable|provider|terraform|locals|output|data|module|condition|provisioner|target|custom_provider|authz_extension|required_providers)$/,
  python: /^(from|import|def|for|if|in|and|or|not|del|return|print|True|False|None|as|with)$/,
  json: /^(true|false|null)$/,
};

const TOKEN =
  /(https?:\/\/[^\s"'\\]+)|("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')|((?:^|(?<=\s))--?[A-Za-z][\w.-]*)|(\$\{[^}]*\}|\$\([^)]*\)|\$[A-Z_]+)|\b([A-Za-z_][\w-]*)\b|(\\$)/g;

function highlight(line: string, lang: Lang): ReactNode[] {
  if (/^\s*#/.test(line) || /^\s*\/\//.test(line)) return [<span key="c" className="tk-comment">{line}</span>];
  const out: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(line))) {
    if (m[0] === "") {
      TOKEN.lastIndex++;
      continue;
    }
    const [, url, dq, sq, flag, sub, word, cont] = m;
    let cls = "";
    if (url) cls = "tk-url";
    else if (dq) cls = /^\s*:/.test(line.slice(m.index + dq.length)) ? "tk-key" : "tk-str";
    else if (sq) cls = "tk-str";
    else if (flag) cls = lang === "shell" ? "tk-flag" : "";
    else if (sub) cls = "tk-sub";
    else if (cont) cls = "tk-cont";
    else if (word) {
      if (KW[lang].test(word)) cls = "tk-cmd";
      else if (/^(GET|POST|PATCH|PUT|DELETE)$/.test(word)) cls = "tk-verb";
      else if (/^(true|false|null|None|True|False)$/.test(word)) cls = "tk-lit";
      else if (lang === "hcl" && /^\s*[A-Za-z_][\w-]*\s*=/.test(line) && line.trimStart().startsWith(word)) cls = "tk-key";
    }
    if (!cls) continue;
    if (m.index > last) out.push(line.slice(last, m.index));
    out.push(
      <span key={m.index} className={cls}>
        {m[0]}
      </span>,
    );
    last = m.index + m[0].length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

export function CodeView({ code, lang, label, maxHeight }: { code: string; lang: Lang; label: string; maxHeight?: number }) {
  const lines = code.replace(/\n$/, "").split("\n");
  return (
    <div className="codeview">
      <div className="codeview-bar">
        <span className="codeview-label">{label}</span>
        <CopyButton getText={() => code} ariaLabel={`Copy ${label}`} className="mini-btn" />
      </div>
      <pre className="code code-full" style={maxHeight ? { maxHeight, overflow: "auto" } : undefined} aria-label={label}>
        {lines.map((l, i) => (
          <div key={i} className="code-line">
            <span className="code-ln" aria-hidden="true">
              {i + 1}
            </span>
            <span className="code-src">{highlight(l, lang)}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}
