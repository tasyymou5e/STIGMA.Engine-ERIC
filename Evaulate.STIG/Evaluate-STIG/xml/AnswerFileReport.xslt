<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="3.0"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" />
  <xsl:template match="/AnswerFiles">
    <html>
      <xsl:variable name="LogoBase64">iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAABEnpUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjalVFbbgMhDPznFD0C9hgDxyH7kHqDHr+zwG66UfJRS5jxGPwM28/3Hr4OASxYysWre6RYtaqNoMQhj64lWtdd3KZP7ny4HEoKvDHMqpPfyBPrMvmZRM73Z6ATSCNKT8cyE8jjhZ8BtbwGmhVARua4DnudgaCDl2lvs1KvJd9a2z3epTxPLlnR3NDMTMydOGty0ySoPA1ZF2+8LSAjwWGoUGJDAXTJ/EwbiPQqtYDZ90XrkSuNJdzs0LeVua81sQOobvwUqYEyWsNxEgMLpGvTeOF6VIN6BGLP3L/GzE9zXpyHnBv4O9DrfiO9ov/M4tMowrtZhF8uA44HACq7LgAAAYRpQ0NQSUNDIHByb2ZpbGUAAHicfZE9SMNAHMVfW6Wi9Qs7iDhkqJ3soiKOpYpFsFDaCq06mFz6BU0akhQXR8G14ODHYtXBxVlXB1dBEPwAcRecFF2kxP8lhRYxHhz34929x907wNuoMMXoigKKauqpeEzI5lYF/yv6MIAhDCMsMkNLpBczcB1f9/Dw9S7Cs9zP/Tn65bzBAI9AHGWabhJvEM9umhrnfeIgK4ky8TnxpE4XJH7kuuTwG+eizV6eGdQzqXniILFQ7GCpg1lJV4hniEOyolK+N+uwzHmLs1KpsdY9+QsDeXUlzXWa44hjCQkkIUBCDWVUYCJCq0qKgRTtx1z8Y7Y/SS6JXGUwciygCgWi7Qf/g9/dGoXpKScpEAO6XyzrYwLw7wLNumV9H1tW8wTwPQNXattfbQBzn6TX21roCBjcBi6u25q0B1zuAKNPmqiLtuSj6S0UgPcz+qYcMHIL9K45vbX2cfoAZKir5Rvg4BAIFyl73eXdPZ29/Xum1d8PsDFyv/JRsSkAAA8gaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIKICAgIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiCiAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgICB4bWxuczpHSU1QPSJodHRwOi8vd3d3LmdpbXAub3JnL3htcC8iCiAgICB4bWxuczpwZGY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGRmLzEuMy8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgeG1wTU06RG9jdW1lbnRJRD0iZ2ltcDpkb2NpZDpnaW1wOmQ5M2QwMzNkLThjZTUtNDFlZi1hYWU1LTY5ZWMxMzdkNmU3ZCIKICAgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5ZDZjOTA5MS00MzAzLTRlMjMtOTRjMi05YzAzN2E4NTczNDYiCiAgIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0MDAwZGExZS0zNjRmLTRiYjAtYTRmNi02MTNmYjE1N2RmZDciCiAgIGRjOkZvcm1hdD0iaW1hZ2UvcG5nIgogICBHSU1QOkFQST0iMi4wIgogICBHSU1QOlBsYXRmb3JtPSJXaW5kb3dzIgogICBHSU1QOlRpbWVTdGFtcD0iMTc2MzEzNzIwNDEyMDU4NCIKICAgR0lNUDpWZXJzaW9uPSIyLjEwLjM4IgogICBwZGY6QXV0aG9yPSJSZWJlY2NhIElyZWxhbmQiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiCiAgIHhtcDpDcmVhdG9yVG9vbD0iR0lNUCAyLjEwIgogICB4bXA6TWV0YWRhdGFEYXRlPSIyMDI1OjExOjE0VDExOjE5OjQ5LTA1OjAwIgogICB4bXA6TW9kaWZ5RGF0ZT0iMjAyNToxMToxNFQxMToxOTo0OS0wNTowMCI+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjkxOTgyYmNhLTc2YzgtNGUzMC1hYzBjLTVkNjA2ZWUxNzJkYyIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChXaW5kb3dzKSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyMy0wNS0yMFQxMzowMTowMyIvPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo1ZGY5YmQwNi1hMDNlLTQyNzMtYjI3OS1lOTZiNWE2NGZiMTIiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjUtMTEtMTRUMTE6MjA6MDQiLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogICA8ZGM6dGl0bGU+CiAgICA8cmRmOkFsdD4KICAgICA8cmRmOmxpIHhtbDpsYW5nPSJ4LWRlZmF1bHQiPlVudGl0bGVkICg2IMOXIDYgaW4pIC0gMjwvcmRmOmxpPgogICAgPC9yZGY6QWx0PgogICA8L2RjOnRpdGxlPgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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</xsl:variable>
      <head>
        <title>Evaluate-STIG Answer File Report</title>
        <script>
          /* Ensure page is always scrolled to top on load */
          if (history.scrollRestoration) {
              history.scrollRestoration = 'manual';
          }
        </script>
        <link rel="icon" type="image/x-icon" href="data:image/x-icon;base64,{$LogoBase64}" />
        <style type="text/css">
          /*
          ==========================================================================
            1. Global Styles and Variables
          ========================================================================== */
          :root {
            /* Colors */
            --body-bg: #f5f5f5;
            --body-color: #707070;
            --eval-stig-bg: #38b6ff;
            --eval-stig-color: #ffffff;
            --text-light-color: #ffffff;
            --main-elements-bg: #ffffff;
            --table-header-bg: #343a40;
            --table-header-color: #d8d7d7;
            --border-md-color: #e0e0e0;

            /* Hover Colors */
            --file-header-hover-bg: rgba(0, 123, 255, 0.05);

            /* Radii and Shadows*/
            --radius-sm: 5px;
            --radius-md: 9px;
            --radius-lg: 12px;
            --shadow-lt: rgba(0, 0, 0, 0.05);
            --shadow-md: rgba(0, 0, 0, 0.1);
            --shadow-dk: rgba(0, 0, 0, 0.2);
          }

          body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 10px;
            background: var(--body-bg);
            color: var(--body-color);
          }

          html {
            scroll-behavior: smooth;
          }

          /*
          ==========================================================================
            2. Animations
          ========================================================================== */
          @keyframes disaFadeIn {
            from {
              opacity: 0;
              transform: translateY(20px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          /*
          ==========================================================================
            3. Main layout
          ========================================================================== */
          #dashboard {
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
          }

          #dashboard .dashboard-header {
            background: linear-gradient(90deg, var(--eval-stig-bg), #b3d9ff);
            padding: 10px 30px 10px 10px;
            border-radius: var(--radius-md);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 8px var(--shadow-md);
            margin-bottom: 30px;
          }

          .dashboard-header .logo {
            font-size: 2.4em;
            font-weight: bold;
            color: var(--text-light-color);
          }

          dashboard-header .header-right {
            font-size: 1em;
          }

          .dashboard-container {
            max-width: 1600px;
            margin: 0 auto;
            background: var(--main-elements-bg);
            border-radius: var(--radius-md);
            padding: 30px;
            box-shadow: 0 8px 16px var(--shadow-md);
            animation: disaFadeIn 0.5s ease-out;
          }

          .column-headers {
            display: grid;
            grid-template-columns: 1fr 1fr 220px;
            gap: 20px;
            padding: 12px 15px;
            background-color: var(--table-header-bg);
            color: var(--table-header-color);
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.85em;
            border-radius: var(--radius-md) var(--radius-md) 0 0;
          }

          .column-headers span:nth-child(2) {
            text-align: left;
          }

          .column-headers span:nth-child(3) {
            text-align: right;
          }

          .file-list {
            border: 1px solid var(--border-md-color);
            border-top: none;
            border-radius: 0 0 var(--radius-md) var(--radius-md);
            overflow: hidden;
          }

          .file-entry {
            border-bottom: 1px solid var(--border-md-color);
          }

          .file-entry:last-child {
            border-bottom: none;
          }

          .file-header {
            display: grid;
            grid-template-columns: 1fr 1fr 220px;
            gap: 20px;
            padding: 12px 15px;
            align-items: center;
            cursor: pointer;
            user-select: none;
            -webkit-user-select: none;
            -ms-user-select: none;
            transition: background-color 0.2s ease;
          }

          .file-header:hover {
            background-color: var(--file-header-hover-bg);
          }

          .file-header .file-name {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: bold;
            font-size: 14px;
          }

          .file-header .file-name .arrow {
            width: 16px;
            text-align: center;
            font-size: 12px;
            transition: transform 0.2s ease;
            display: inline-block;
          }

          .file-header .file-name .arrow.expanded {
            transform: rotate(90deg);
          }

          .file-header .path {
            text-align: left;
            font-size: 14px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }

          .file-header .modified {
            text-align: right;
            font-size: 14px;
          }

          .field-row {
            padding: 4px 15px;
            line-height: 1.6;
            font-size: 14px;
          }

          .field-label {
            font-weight: bold;
          }

          .field-value {
            /* No extra styling at this time */
          }

          .code-block {
            background: var(--body-bg);
            color: var(--body-color);
            border-left: 4px solid var(--eval-stig-bg);
            padding: 12px 16px;
            margin: 6px 0;
            font-family: monospace;
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-x: auto;
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
          }

          .collapsible {
            max-height: 5000px;
            opacity: 1;
            overflow: hidden;
            transition:
              max-height 0.25s ease,
              opacity 0.25s ease;
          }

          .collapsible.hide {
            max-height: 0;
            opacity: 0;
          }

          /*
          ==========================================================================
            4. Interactive Elements
          ========================================================================== */
          .toggle-btn {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 15px;
            cursor: pointer;
            user-select: none;
            -webkit-user-select: none;
            -ms-user-select: none;
            font-family: inherit;
            font-size: 14px;
            font-weight: bold;
            border: none;
            background: none;
            transition: background-color 0.2s ease;
            line-height: 1.6;
          }

          .toggle-btn:hover {
            background-color: var(--file-header-hover-bg);
          }

          .toggle-btn .arrow {
            width: 16px;
            text-align: center;
            font-size: 12px;
            transition: transform 0.2s ease;
            display: inline-block;
          }

          .toggle-btn.expanded .arrow {
            transform: rotate(90deg);
          }

          .toggle-btn .section-value {
            font-weight: normal;
          }

          .topbtn {
            position: fixed;
            bottom: 20px;
            right: 30px;
            z-index: 99;
            font-size: 18px;
            border: none;
            outline: none;
            padding: 10px;
            border-radius: 50px;
            background-color: var(--eval-stig-bg);
            color: var(--eval-stig-color);
            transition: background-color 0.3s, transform 0.3s;
            cursor: pointer;
            opacity: 0;
            visibility: hidden;
            transition: filter 0.2s ease, opacity 0.25s ease-in-out, visibility 0.25s ease-in-out, transform 0.25s;
          }

          .topbtn.visible {
            opacity: 1;
            visibility: visible;
          }

          .topbtn:hover {
            filter: brightness(0.93);
            transform: scale(1.1);
          }

          /*
          ==========================================================================
            5. Indents
          ========================================================================== */
          .indent-1 {
            padding-left: 40px;
          }

          .indent-2 {
            padding-left: 60px;
          }

          .indent-3 {
            padding-left: 80px;
          }

          .indent-4 {
            padding-left: 100px;
          }

          .indent-5 {
            padding-left: 120px;
          }
        </style>
      </head>
      <body>
        <div class="dashboard-container">
          <button id="topbtn" class="topbtn" onclick="topFunction()" title="Back to Top">&#9650;</button>
          <div id="dashboard">
            <div class="dashboard-header">
              <div class="logo">
                <img style="vertical-align: middle;" src="data:image/png;base64,{$LogoBase64}" /> Evaluate-STIG Answer File Report
              </div>
              <div class="header-right">
                <span>
                  <xsl:value-of select="/AnswerFiles/@Created"/>
                </span>
              </div>
            </div>
            <div class="dashboard-container">
              <div class="column-headers">
                <span>Answer File</span>
                <span>Path</span>
                <span>Modified</span>
              </div>
              <div class="file-list">
                <xsl:for-each select="AnswerFile">
                  <xsl:apply-templates select="." />
                </xsl:for-each>
              </div>
            </div>
          </div>
        </div>
        <script>
          function toggleCollapsible(headerEl) {
            var contentEl = headerEl.nextElementSibling;
            if (!contentEl || !contentEl.classList.contains("collapsible"))
              return;
            var isToggleBtn = headerEl.classList.contains("toggle-btn");
            var arrow = headerEl.querySelector(".arrow");
            if (contentEl.classList.contains("hide")) {
              contentEl.classList.remove("hide");
              if (isToggleBtn) headerEl.classList.add("expanded");
              if (arrow) arrow.classList.add("expanded");
            } else {
              contentEl.classList.add("hide");
              if (isToggleBtn) headerEl.classList.remove("expanded");
              if (arrow) arrow.classList.remove("expanded");
            }
          }

          function topFunction(){
            document.body.scrollTop = 0;
            document.documentElement.scrollTop = 0;
          }

          window.addEventListener('scroll', function () {
            const topbutton = document.getElementById('topbtn');
            if (!topbutton) return;

            const scrollTop = document.documentElement.scrollTop || document.body.scrollTop;
            const docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
            const scrollPercent = scrollTop / docHeight;

            if (window.scrollY > 100) {
              topbutton.classList.add('visible');
            } else {
              topbutton.classList.remove('visible');
            }
          });
        </script>
      </body>
    </html>
  </xsl:template>
  <xsl:template match="AnswerFile">
    <div class="file-entry">
      <div class="file-header" onclick="toggleCollapsible(this)">
        <div class="file-name">
          <span class="arrow">&#9654;</span>
          <span>
            <xsl:value-of select="@FileName" />
          </span>
        </div>
        <span class="path">
          <xsl:value-of select="Path" />
        </span>
        <span class="modified">
          <xsl:value-of select="Modified" />
        </span>
      </div>
      <div class="collapsible hide">
        <div class="field-row indent-1">
          <span class="field-label">XmlComment: </span>
          <span class="field-value">
            <xsl:value-of select="Comment" />
          </span>
        </div>
        <div class="field-row indent-1">
          <span class="field-label">ShortName: </span>
          <span class="field-value">
            <xsl:value-of select="ShortName" />
          </span>
        </div>
        <xsl:for-each select="Vuln">
          <xsl:apply-templates select="." />
        </xsl:for-each>
      </div>
    </div>
  </xsl:template>
  <xsl:template match="Vuln">
    <div class="toggle-btn indent-2" onclick="toggleCollapsible(this)">
      <span class="arrow">&#9654;</span>
      <span>
        <xsl:value-of select="@ID" />
      </span>
    </div>
    <div class="collapsible hide">
      <div class="field-row indent-3">
        <span class="field-label">XmlComment: </span>
        <span class="field-value">
          <xsl:value-of select="Comment" />
        </span>
      </div>
      <xsl:for-each select="AnswerKey">
        <xsl:apply-templates select="." />
      </xsl:for-each>
    </div>
  </xsl:template>
  <xsl:template match="AnswerKey">
    <div class="toggle-btn indent-3" onclick="toggleCollapsible(this)">
      <span class="arrow">&#9654;</span>
      <span class="field-label">AnswerKey: </span>
      <span class="section-value">
        <xsl:value-of select="@Name" />
      </span>
    </div>
    <div class="collapsible hide">
      <div class="field-row indent-4">
        <span class="field-label">XmlComment: </span>
        <span class="field-value">
          <xsl:value-of select="Comment" />
        </span>
      </div>
      <xsl:for-each select="Answer">
        <xsl:apply-templates select="." />
      </xsl:for-each>
    </div>
  </xsl:template>
  <xsl:template match="Answer">
    <div class="toggle-btn indent-4" onclick="toggleCollapsible(this)">
      <span class="arrow">&#9654;</span>
      <span class="field-label">Index: </span>
      <span class="section-value">
        <xsl:value-of select="@Index" />
      </span>
    </div>
    <div class="collapsible hide">
      <div class="field-row indent-5">
        <span class="field-label">XmlComment: </span>
        <span class="field-value">
          <xsl:value-of select="Comment" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ExpectedStatus: </span>
        <span class="field-value">
          <xsl:value-of select="ExpectedStatus" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">Hostname: </span>
        <span class="field-value">
          <xsl:value-of select="Hostname" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">Instance: </span>
        <span class="field-value">
          <xsl:value-of select="Instance" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">Database: </span>
        <span class="field-value">
          <xsl:value-of select="Database" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">Site: </span>
        <span class="field-value">
          <xsl:value-of select="Site" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ResultHash: </span>
        <span class="field-value">
          <xsl:value-of select="ResultHash" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ValidationCode: </span>
        <span class="field-value">
          <xsl:choose>
            <xsl:when test="normalize-space(ValidationCode)">
              <pre class="code-block">
                <xsl:value-of select="ValidationCode" />
              </pre>
            </xsl:when>
            <xsl:otherwise></xsl:otherwise>
          </xsl:choose>
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ValidTrueStatus: </span>
        <span class="field-value">
          <xsl:value-of select="ValidTrueStatus" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ValidTrueComment: </span>
        <span class="field-value">
          <xsl:value-of select="ValidTrueComment" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ValidFalseStatus: </span>
        <span class="field-value">
          <xsl:value-of select="ValidFalseStatus" />
        </span>
      </div>
      <div class="field-row indent-5">
        <span class="field-label">ValidFalseComment: </span>
        <span class="field-value">
          <xsl:value-of select="ValidFalseComment" />
        </span>
      </div>
    </div>
  </xsl:template>
</xsl:stylesheet>