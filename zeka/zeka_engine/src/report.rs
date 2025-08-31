pub const REPORT_TEMPLATE: &str = r#"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ZekaEngine: {{ title }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{--bg:#fafbff;--panel:#ffffff;--text:#0b0c0e;--muted:#606671;--line:#e7eaf0;--chip:#f3f5f9;}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0;background:var(--bg);color:var(--text)}
    body{font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
    .wrap{max-width:760px;margin:48px auto;padding:0 20px}
    header{margin-bottom:20px}
    h1{margin:0 0 6px;font-size:24px;letter-spacing:.2px}
    .stamp{color:var(--muted);font-size:13px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}
    ul.vulns{list-style:none;margin:0;padding:0;display:grid;gap:8px}
    .summary {margin: 4px 0 12px;color: black;font-size: 16px;}
    .empty{color: var(--muted); text-align: center; padding: 24px 8px;}
    .vuln{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:#fff}
    .vtext{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .pts{font-size:12px;color:var(--muted);background:var(--chip);border:1px solid var(--line);padding:4px 8px;border-radius:999px;white-space:nowrap}
    footer.footer{margin-top:24px;color:var(--muted);font-size:12px;text-align:center}
  </style>
</head>
<body>
  <main class="wrap">
    <header>
      <h1>{{ title }}</h1>
      <div class="stamp">Report generated at: {{ timestamp }}</div>
    </header>

    <section class="card">
      {% if vulns|length == 0 %}
        <div class="empty">You have not scored any points yet.</div>
      {% else %}
        <div class="summary">{{ vulns|length }} vulnerabilit{% if vulns|length == 1 %}y{% else %}ies{% endif %} scored for a total of {{ total }} pts</div>
        <ul class="vulns">
          {% for v in vulns %}
            <li class="vuln">
              <span class="vtext">{{ v.desc if v is mapping else v }}</span>
              {% if v is mapping and v.points is defined %}
                <span class="pts">{{ v.points }} pts</span>
              {% endif %}
            </li>
          {% endfor %}
        </ul>
      {% endif %}
    </section>

    <footer class="footer"><a href="https://github.com/ajiang-xyz/ZekaEngine">ZekaEngine</a> is an open source project written by Alex Jiang.</footer>
  </main>
</body>
</html>
"#;
