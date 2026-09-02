<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="3.0"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" />
  <xsl:template match="/">
    <html>
      <xsl:variable name="LogoBase64">iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAABEnpUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjalVFbbgMhDPznFD0C9hgDxyH7kHqDHr+zwG66UfJRS5jxGPwM28/3Hr4OASxYysWre6RYtaqNoMQhj64lWtdd3KZP7ny4HEoKvDHMqpPfyBPrMvmZRM73Z6ATSCNKT8cyE8jjhZ8BtbwGmhVARua4DnudgaCDl2lvs1KvJd9a2z3epTxPLlnR3NDMTMydOGty0ySoPA1ZF2+8LSAjwWGoUGJDAXTJ/EwbiPQqtYDZ90XrkSuNJdzs0LeVua81sQOobvwUqYEyWsNxEgMLpGvTeOF6VIN6BGLP3L/GzE9zXpyHnBv4O9DrfiO9ov/M4tMowrtZhF8uA44HACq7LgAAAYRpQ0NQSUNDIHByb2ZpbGUAAHicfZE9SMNAHMVfW6Wi9Qs7iDhkqJ3soiKOpYpFsFDaCq06mFz6BU0akhQXR8G14ODHYtXBxVlXB1dBEPwAcRecFF2kxP8lhRYxHhz34929x907wNuoMMXoigKKauqpeEzI5lYF/yv6MIAhDCMsMkNLpBczcB1f9/Dw9S7Cs9zP/Tn65bzBAI9AHGWabhJvEM9umhrnfeIgK4ky8TnxpE4XJH7kuuTwG+eizV6eGdQzqXniILFQ7GCpg1lJV4hniEOyolK+N+uwzHmLs1KpsdY9+QsDeXUlzXWa44hjCQkkIUBCDWVUYCJCq0qKgRTtx1z8Y7Y/SS6JXGUwciygCgWi7Qf/g9/dGoXpKScpEAO6XyzrYwLw7wLNumV9H1tW8wTwPQNXattfbQBzn6TX21roCBjcBi6u25q0B1zuAKNPmqiLtuSj6S0UgPcz+qYcMHIL9K45vbX2cfoAZKir5Rvg4BAIFyl73eXdPZ29/Xum1d8PsDFyv/JRsSkAAA8gaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIKICAgIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiCiAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgICB4bWxuczpHSU1QPSJodHRwOi8vd3d3LmdpbXAub3JnL3htcC8iCiAgICB4bWxuczpwZGY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGRmLzEuMy8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgeG1wTU06RG9jdW1lbnRJRD0iZ2ltcDpkb2NpZDpnaW1wOmQ5M2QwMzNkLThjZTUtNDFlZi1hYWU1LTY5ZWMxMzdkNmU3ZCIKICAgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5ZDZjOTA5MS00MzAzLTRlMjMtOTRjMi05YzAzN2E4NTczNDYiCiAgIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0MDAwZGExZS0zNjRmLTRiYjAtYTRmNi02MTNmYjE1N2RmZDciCiAgIGRjOkZvcm1hdD0iaW1hZ2UvcG5nIgogICBHSU1QOkFQST0iMi4wIgogICBHSU1QOlBsYXRmb3JtPSJXaW5kb3dzIgogICBHSU1QOlRpbWVTdGFtcD0iMTc2MzEzNzIwNDEyMDU4NCIKICAgR0lNUDpWZXJzaW9uPSIyLjEwLjM4IgogICBwZGY6QXV0aG9yPSJSZWJlY2NhIElyZWxhbmQiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiCiAgIHhtcDpDcmVhdG9yVG9vbD0iR0lNUCAyLjEwIgogICB4bXA6TWV0YWRhdGFEYXRlPSIyMDI1OjExOjE0VDExOjE5OjQ5LTA1OjAwIgogICB4bXA6TW9kaWZ5RGF0ZT0iMjAyNToxMToxNFQxMToxOTo0OS0wNTowMCI+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjkxOTgyYmNhLTc2YzgtNGUzMC1hYzBjLTVkNjA2ZWUxNzJkYyIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChXaW5kb3dzKSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyMy0wNS0yMFQxMzowMTowMyIvPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo1ZGY5YmQwNi1hMDNlLTQyNzMtYjI3OS1lOTZiNWE2NGZiMTIiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjUtMTEtMTRUMTE6MjA6MDQiLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogICA8ZGM6dGl0bGU+CiAgICA8cmRmOkFsdD4KICAgICA8cmRmOmxpIHhtbDpsYW5nPSJ4LWRlZmF1bHQiPlVudGl0bGVkICg2IMOXIDYgaW4pIC0gMjwvcmRmOmxpPgogICAgPC9yZGY6QWx0PgogICA8L2RjOnRpdGxlPgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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</xsl:variable>
      <head>
        <title>Evaluate-STIG Summary Report</title>
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
            --link-color: #007bff;
            --text-light-color: #ffffff;
            --main-elements-bg: #ffffff;
            --table-header-bg: #343a40;
            --table-header-color: #d8d7d7;
            --filter-btn-bg: ##f9f9f9;
            --border-md-color: #e0e0e0;
            --border-dk-color: #c0c0c0;
            --chart-legend-bg: #f7f9fc;

            /* Status and CAT Colors */
            --nr-bg: #f0f0f0;
            --nr-color: #6d6d6d;
            --na-bg: #c8c8c8;
            --na-color: #545454;
            --nf-bg: #d0f0c0;
            --nf-color: #3a751c;
            --o-cat1-bg: #ffa5a5;
            --o-cat1-color: #9f0000;
            --o-cat2-bg: #ffc8a0;
            --o-cat2-color: #994100;
            --o-cat3-bg: #ffffb9;
            --o-cat3-color: #787800;

            /* Risk Level Colors */
            --risk-very-high-bg: #ffa5a5;
            --risk-very-high-color: #9f0000;
            --risk-high-bg: #ffc8a0;
            --risk-high-color: #994100;
            --risk-moderate-bg: #ffffb9;
            --risk-moderate-color: #787800;
            --risk-low-bg: #aed6f1;
            --risk-low-color: #185e8e;
            --risk-very-low-bg: #d0f0c0;
            --risk-very-low-color: #3a751c;

            /* Hover Colors */
            --hover-tooltip-bg: rgba(0, 0, 0, 0.85);
            --hover-tooltip-color: #ffffff;
            --hover-comment-bg: #66C7ff;
            --hover-comment-color: #00507f;
            --hover-filterbtn-bg: #eaeaea;
            --hover-table-header-bg: #4a5568;
            --hover-nr-bg: #dfdfdf;
            --hover-na-bg: #bababa;
            --hover-nf-bg: #c1dfb2;
            --hover-o-cat1-bg: #ed9999;
            --hover-o-cat2-bg: #edba95;
            --hover-o-cat3-bg: #ededad;

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
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(-10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

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

          .dashboard-header .header-right {
            font-size: 1em;
          }

          .dashboard-header .header-right a {
            color: var(--link-color);
            text-decoration: underline;
            cursor: pointer;
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

          .report-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
          }

          .report-header h1 {
            font-size: 2.2em;
          }

          /*
          ==========================================================================
            4. Cards and Tables
          ========================================================================== */
          .card {
            background: var(--main-elements-bg);
            box-shadow: 0 4px 12px var(--shadow-md);
            border-radius: var(--radius-md);
            padding: 14px;
            text-align: center;
            border: 1px solid rgba(0, 0, 0, 0.04);
            transition: box-shadow 0.2s ease, transform 0.2s ease;
          }

          .card h3 {
            margin-bottom: 10px;
            margin-top: 0;
          }

          .scan-detail {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-around;
            align-items: center;
            font-size: 16px;
            background: var(--main-elements-bg);
            padding: 12px 16px;
            border-radius: var(--radius-lg);
            box-shadow: 0 4px 12px var(--shadow-md);
            border: 1px solid rgba(0, 0, 0, 0.04);
          }

          .scan-detail p {
            margin: 5px 10px;
          }

          .ps-card {
            margin-top: 30px;
            position: relative;
            text-align: left;
            box-shadow: 0 4px 12px var(--shadow-md);
          }

          #ps-command-content {
            word-break: keep-all;
            overflow-wrap: break-word;
            hyphens: none;
            -webkit-hyphens: none;
            -ms-hyphens: none;
            background: var(--body-bg);
            border-left: 4px solid var(--eval-stig-bg);
            border-radius: var(--radius-sm);
            padding: 16px 20px;
            margin-top: 10px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            line-height: 1.7;
            text-align: left;
          }

          table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background-color: var(--main-elements-bg);
            border-radius: var(--radius-md);
            overflow: hidden;
          }

          .table-container {
            width: 100%;
            overflow-x: auto;
            margin-top: 30px;
            text-align: center;
            border-radius: var(--radius-md);
            box-shadow: 0 4px 12px var(--shadow-md);
          }

          th,
          td {
            padding: 12px 15px;
            text-align: center;
            font-size: 0.9rem;
            line-height: 1.4;
            border-bottom: 1px solid var(--border-md-color);
          }

          th {
            background-color: var(--table-header-bg);
            color: var(--table-header-color);
            font-weight: bold;
            text-transform: uppercase;
          }

          th,
          .sortheading {
            user-select: none;
            -webkit-user-select: none;
            -ms-user-select: none;
          }

          tr:last-child td {
            border-bottom: none;
          }

          #comp-info table#comp-table {
            width: 100%;
            table-layout: fixed;
            min-width: 1000px;
            border-radius: var(--radius-md);
            word-wrap: break-word;
            white-space: normal;
            overflow: break-word;
          }

          #comp-info table#comp-table thead th {
            position: sticky;
            top: 0;
            z-index: 2;
          }

          #comp-info table#comp-table td {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
          }

          #stig-info table#stig-table {
            border-radius: var(--radius-md);
          }

          #stig-table tr:has(button.toggle-btn.expanded) td {
            border-bottom: none;
          }

          #stig-table td table td {
            border-bottom: 1px solid var(--eval-stig-color);
          }

          #stig-table td table.nested-table tbody tr:last-child td {
            border-bottom: none;
          }

          .nested-table-container {
            margin-bottom: 8px;
            border-radius: var(--radius-md);
            overflow: visible;
            box-shadow: 0 4px 12px var(--shadow-md);
            overflow-x: auto;
            animation: slideDown 0.3s ease-out;
          }

          .nested-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--main-elements-bg);
            border-radius: var(--radius-sm);
            overflow: hidden;
          }

          .nested-table th:nth-child(1) {
            width: 90px;
          }

          .nested-table th:nth-child(2) {
            width: 110px;
          }

          .nested-table th:nth-child(3) {
            width: 120px;
          }

          .nested-table th:nth-child(4) {
            width: 400px;
          }

          .nested-table th:nth-child(5) {
            width: 100px;
          }

          .nested-table th:nth-child(6) {
            width: 130px;
          }

          .nested-table th:nth-child(7) {
            width: 120px;
          }

          .nested-table thead {
            display: table-header-group !important;
          }

          .nested-table thead tr {
            display: table-row !important;
          }

          .nested-table thead th {
            display: table-cell !important;
          }

          .nested-table th.sortheading {
            background-color: var(--table-header-bg) !important;
            color: var(--table-header-color) !important;
            border-bottom: none !important;
            transition: background-color 0.2s ease;
          }

          .nested-table th.sortheading:hover {
            background-color: var(--hover-table-header-bg) !important;
          }

          .nested-table th.sortheading.asc,
          .nested-table th.sortheading.desc {
            background-color: var(--eval-stig-bg) !important;
            color: var(--text-light-color) !important;
          }

          .nested-table th.sortheading.asc::after,
          .nested-table th.sortheading.desc::after {
            background-color: var(--eval-stig-bg) !important;
            color: var(--text-light-color) !important;
          }

          /*
          ==========================================================================
            5. Charts
          ========================================================================== */
          /*stack everything vertically on smaller devices */
          @media (max-width: 1250px) {
            .charts-container {
              flex-direction: column;
              gap: 24px;
              padding: 18px;
            }

            .cat-stacked-section {
              width: 100%;
              height: auto;
            }

            .cat-stacked-section .cat-bar-card {
              width: 100%;
              max-width: 600px;
              flex: none;
            }

            .card-overall {
              width: 100%;
              max-width: 600px;
            }
          }

          canvas {
            max-width: 100%;
            height: auto;
          }

          .card canvas {
            display: block;
            margin: 0 auto;
          }

          .chart-wrapper {
            display: flex;
            justify-content: space-around;
            align-items: flex-start;
            flex-wrap: wrap;
            margin-bottom: 20px;
          }

          .card-overall {
            width: 500px;
            padding: 24px;
            display: flex;
            flex-direction: column;
          }

          .card-overall canvas {
            width: 500px !important;
            height: 500px !important;
          }

          .overall-section {
            display: flex;
            justify-content: center;
            align-items: stretch;
          }

          .cat-stacked-section {
            display: flex;
            flex-direction: column;
            gap: 10px;
            justify-content: space-between;
            height: 100%;
          }

          .cat-stacked-section .cat-bar-card {
            width: 700px;
            padding: 24px 28px;
            display: flex;
            flex-direction: column;
            align-items: stretch;
            flex: 1;
            justify-content: center;
          }

          .cat-stacked-section .cat-bar-card h3 {
            margin-bottom: 16px;
            margin-top: 0;
            text-align: left;
          }

          .cat-stacked-section .chart-content {
            display: flex;
            flex-direction: column;
            gap: 8px;
          }

          .stacked-bar-container {
            width: 100%;
          }

          .stacked-bar-wrapper {
            width: 100%;
            height: 75px;
            border-radius: var(--radius-md);
            overflow: hidden;
            display: flex;
            box-shadow: inset 0 1px 3px var(--shadow-md);
          }

          .bar-segment {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            font-weight: 600;
            transition: filter 0.2s ease, flex 0.3s ease;
            cursor: default;
            min-width: 0;
            position: relative;
          }

          .bar-segment:hover {
            filter: brightness(0.93);
          }

          .bar-segment span {
            opacity: 0;
            transition: opacity 0.2s ease;
          }

          .bar-segment:hover span {
            opacity: 1;
          }

          .bar-legend {
            list-style: none;
            padding: 6px 10px;
            margin: 8px 0px 5px 0px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px 24px;
            font-size: 0.95rem;
            pointer-events: none;
            justify-content: center;
            background: var(--chart-legend-bg);
            border-radius: var(--radius-md);
            box-shadow: 0 2px 6px var(--shadow-lt);
          }

          .bar-legend li {
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 2px 0;
          }

          .bar-legend .legend-color {
            width: 18px;
            height: 18px;
            border-radius: var(--radius-sm);
            flex-shrink: 0;
          }

          .bar-legend .legend-count {
            font-weight: bold;
          }

          .charts-container {
            display:flex;
            justify-content:center;
            align-items:stretch;
            gap: 40px;
            flex-wrap: wrap;
            margin-bottom: 5px;
            padding: 24px 16px;
            border-radius: var(--radius-lg);
          }

          .card .legend {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 4px;
            padding: 6px 10px;
            margin-top: 16px;
            background: var(--chart-legend-bg);
            border-radius: var(--radius-md);
            box-shadow: 0 2px 6px var(--shadow-lt);
            list-style: none;
          }

          .card .legend-count {
            font-weight: bold;
            margin-left: 2px;
          }

          .card .legend li {
            display: flex;
            align-items: center;
            font-size: 0.85rem;
            padding: 4px 8px;
            border-radius: var(--radius-sm);
            transition: background 0.2s;
            cursor: default;
          }

          .card .legend-color {
            display: inline-block;
            width: 12px;
            height: 12px;
            margin-right: 5px;
            border: 1px solid var(--border-dk-color);
            border-radius: var(--radius-sm);
            box-shadow: 0 1px 2px var(--shadow-md);
          }

          /*
          ==========================================================================
            6. Interactive Elements
          ========================================================================== */
          .risk-level {
            position: relative;
            user-select: none;
            -webkit-user-select: none;
            -ms-user-select: none;
            font-size: 1em;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 30px;
            border: 1px solid var(--border-dk-color);
            transition: filter 0.2s ease, opacity 0.25s ease-in-out, visibility 0.25s ease-in-out, transform 0.25s;
          }

          .risk-level:hover {
            filter: brightness(0.93);
            transform: scale(1.1);
          }

          .risk-level::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 130%;
            left: 50%;
            transform: translateX(-50%);
            display: block;
            min-width: 180px;
            max-width: 300px;
            white-space: normal;
            background: var(--hover-tooltip-bg);
            color: var(--hover-tooltip-color);
            padding: 6px 10px;
            border-radius: var(--radius-sm);
            text-align: center;
            visibility: hidden;
            opacity: 0;
            z-index: 9999;
            transition: opacity 0.25s ease, transform 0.25s ease;
          }

          .risk-level:hover::after {
            opacity: 1;
            visibility: visible;
            transform: translateX(-50%) translateY(-8px);
          }

          .chart-tooltip {
            position: absolute;
            padding: 6px 10px;
            background: var(--hover-tooltip-bg);
            color: var(--hover-tooltip-color);
            border-radius: var(--radius-sm);
            font-size: 13px;
            pointer-events: none;
            opacity: 0;
            transform: scale(0.8) translateY(-10px);
            transition: opacity 0.25s ease, transform 0.25s ease;
            z-index: 9999;
          }

          .filter-btn {
            padding: 6px 14px;
            font-size: 0.8rem;
            border: 1px solid var(--border-md-color);
            background: var(--filter-btn-bg);
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.25s ease;
          }

          .filter-btn:hover {
            background: var(--hover-filterbtn-bg);
          }

          .filter-btn.active {
            background: var(--eval-stig-bg);
            color: var(--text-light-color);
            border-color: var(--eval-stig-bg);
            font-weight: 600;
          }

          .nested-table-search {
            padding: 6px 12px;
            background-color: var(--filter-btn-bg);
            border: 1px solid var(--border-md-color);
            border-radius: var(--radius-sm);
            min-width: 220px;
          }

          .no-results {
            text-align: center;
            font-style: italic;
            margin: 8px 0px 8px 0px;
          }

          .topbtn.visible {
            opacity: 1;
            visibility: visible;
          }

          .topbtn:hover {
            filter: brightness(0.93);
            transform: scale(1.1);
          }

          .toggle-btn {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: inherit;
            font-size: 14px;
            font-weight: bold;
            border: none;
            background: none;
            cursor: pointer;
            text-align: left;
          }

          .toggle-btn .arrow::before {
            content: "\25b6"
          }

          .toggle-btn .arrow {
            width: 16px;
            text-align: center;
            font-size: 12px;
            transition: transform 0.2s ease;
          }

          .toggle-btn.expanded .arrow {
            transform: rotate(90deg);
          }

          .toggle-btn:hover {
            background-color: rgba(0, 123, 255, 0.05);
          }

          .sortheading {
            cursor: pointer;
            position: relative;
            transition: background-color 0.2s ease, color 0.2s ease;
          }

          .sortheading.asc::after {
            content: " \25B2";
          }

          .sortheading.desc::after {
            content: " \25Bc";
          }

          .group-btn {
            margin: 10px 0px 10px 10px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
          }

          .CellWithComment {
            position: relative;
            cursor: default;
            transition: background-color 0.2s ease;
          }

          .CellComment {
            visibility: hidden;
            position: fixed;
            z-index: 9999;
            pointer-events: none;
            background: var(--hover-comment-bg);
            border-radius: var(--radius-sm);
            padding: 10px 16px;
            color: var(--hover-comment-color);
            font-size: 0.85rem;
            box-shadow: 0 2px 8px var(--shadow-dk);
            opacity: 0;
            transition: opacity 0.2s ease, visibility 0.3s ease;
            width: max-content;
            max-width: 300px;
            text-align: left;
            white-space: normal;
            word-wrap: break-word;
            overflow-wrap: break-word;
          }

          .CellComment::after {
            content: '';
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translate(-50%);
            border: 6px solid transparent;
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

          /*
          ==========================================================================
            7. Risk and Status Coloring
          ========================================================================== */
          .risk-very-high {
            background-color: var(--risk-very-high-bg);
            color: var(--risk-very-high-color);
          }

          .risk-high {
            background-color: var(--risk-high-bg);
            color: var(--risk-high-color);
          }

          .risk-moderate {
            background-color: var(--risk-moderate-bg);
            color: var(--risk-moderate-color);
          }

          .risk-low {
            background-color: var(--risk-low-bg);
            color: var(--risk-low-color);
          }

          .risk-very-low {
            background-color: var(--risk-very-low-bg);
            color: var(--risk-very-low-color);
          }

          .status-NR {
            background-color: var(--nr-bg);
            color: var(--nr-color);
          }

          .status-NR:hover {
            background-color: var(--hover-nr-bg);
          }

          .status-NA {
            background-color: var(--na-bg);
            color: var(--na-color);
          }

          .status-NA:hover {
            background-color: var(--hover-na-bg);
          }

          .status-NF {
            background-color: var(--nf-bg);
            color: var(--nf-color);
          }

          .status-NF:hover {
            background-color: var(--hover-nf-bg);
          }

          .status-O_high {
            background-color: var(--o-cat1-bg);
            color: var(--o-cat1-color);
          }

          .status-O_high:hover {
            background-color: var(--hover-o-cat1-bg);
          }

          .status-O_med {
            background-color: var(--o-cat2-bg);
            color: var(--o-cat2-color);
          }

          .status-O_med:hover {
            background-color: var(--hover-o-cat2-bg);
          }

          .status-O_low {
            background-color: var(--o-cat3-bg);
            color: var(--o-cat3-color);
          }

          .status-O_low:hover {
            background-color: var(--hover-o-cat3-bg);
          }
        </style>
      </head>
      <body>
        <xsl:variable name="Summaries" select="Summaries/Summary" />
        <xsl:variable name="SummaryCount" select="count($Summaries)" />
        <xsl:for-each select="Summaries/Summary">
          <xsl:variable name="ComputerName" select="Computer/Name" />
          <div class="dashboard-container">
            <button id="topbtn" class="topbtn" onclick="topFunction()" title="Back to Top">&#9650;</button>
            <div id="dashboard">
              <div class="dashboard-header">
                <div class="logo">
                  <img style="vertical-align: middle;" src="data:image/png;base64,{$LogoBase64}" /> Evaluate-STIG Summary Report
                </div>
                <div class="header-right">
                  <span>
                    <xsl:value-of select="Computer/ScanDate"/>
                  </span> |
                  <a href="#stig-info"> View Scan</a>
                </div>
              </div>
              <div class="dashboard-container">
                <div class="report-header">
                  <h1></h1>
                  <span class="risk-level">
                    <xsl:value-of select="Computer/Score/RiskRating"/>
                  </span>
                </div>
                <div class="charts-container">
                  <div class="overall-section">
                    <div class="card card-overall">
                      <h3>Overall Scan</h3>
                      <canvas id="pieChartOverall" width="480" height="480"></canvas>
                      <ul id="legend-pieChartOverall" class="legend"></ul>
                    </div>
                  </div>
                  <div class="cat-stacked-section">
                    <div class="card cat-bar-card">
                      <h3>CAT I </h3>
                      <div class="chart-content" style="flex-direction: column; align-items: stretch;">
                        <div id="barChart1" class="stacked-bar-container"></div>
                        <ul id="legend-barChart1" class="bar-legend"></ul>
                      </div>
                    </div>
                    <div class="card cat-bar-card">
                      <h3>CAT II</h3>
                      <div class="chart-content" style="flex-direction: column; align-items: stretch;">
                        <div id="barChart2" class="stacked-bar-container"></div>
                        <ul id="legend-barChart2" class="bar-legend"></ul>
                      </div>
                    </div>
                    <div class="card cat-bar-card">
                      <h3>CAT III</h3>
                      <div class="chart-content" style="flex-direction: column; align-items: stretch;">
                        <div id="barChart3" class="stacked-bar-container"></div>
                        <ul id="legend-barChart3" class="bar-legend"></ul>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="scan-detail">
                  <p>
                    <strong>Device Name: </strong>
                    <xsl:value-of select="Computer/Name" />
                  </p>
                  <p>
                    <strong>Scan Date: </strong>
                    <xsl:value-of select="Computer/ScanDate" />
                  </p>
                  <p>
                    <strong>Eval-STIG Version: </strong>
                    <xsl:value-of select="Computer/EvalSTIGVer" />
                  </p>
                  <p>
                    <strong>Scan Type: </strong>
                    <xsl:value-of select="Computer/ScanType" />
                  </p>
                  <p>
                    <strong>User Profile: </strong>
                    <xsl:value-of select="Computer/ScannedUserProfile" />
                  </p>
                </div>
                <div class="card ps-card" id="info-card">
                  <h3>Command Executed: </h3>
                  <div id ="ps-command-content">
                    <xsl:value-of select="Computer/CommandExecuted" />
                  </div>
                </div>
                <div id="comp-info" class="table-container">
                  <h2>Computer Information</h2>
                  <table id="comp-table">
                    <thead>
                      <tr>
                        <th>Model</th>
                        <th>Serial Number</th>
                        <th>BIOS Version</th>
                        <th>OS Name</th>
                        <th>OS Version</th>
                        <th>OS Architecture</th>
                        <th>CPU Architecture</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <xsl:for-each select="Computer">
                          <td>
                            <xsl:value-of select="Model" />
                          </td>
                          <td>
                            <xsl:value-of select="SerialNumber" />
                          </td>
                          <td>
                            <xsl:value-of select="BIOSVersion" />
                          </td>
                          <td>
                            <xsl:value-of select="OSName" />
                          </td>
                          <td>
                            <xsl:value-of select="OSVersion" />
                          </td>
                          <td>
                            <xsl:value-of select="OSArchitecture" />
                          </td>
                          <td>
                            <xsl:value-of select="CPUArchitecture" />
                          </td>
                        </xsl:for-each>
                      </tr>
                    </tbody>
                    <thead>
                      <tr>
                        <th>Interface Index</th>
                        <th>Caption</th>
                        <th>MAC Address</th>
                        <th>IPv4 Address</th>
                        <th colspan="3">IPv6 Address</th>
                      </tr>
                    </thead>
                    <tbody>
                      <xsl:for-each select="Computer/NetworkAdapters/Adapter">
                        <tr>
                          <td>
                            <xsl:value-of select="@InterfaceIndex" />
                          </td>
                          <td>
                            <xsl:value-of select="Caption" />
                          </td>
                          <td>
                            <xsl:value-of select="MACAddress" />
                          </td>
                          <td>
                            <xsl:value-of select="IPv4Addresses" />
                          </td>
                          <td colspan="3">
                            <xsl:value-of select="IPv6Addresses" />
                          </td>
                        </tr>
                      </xsl:for-each>
                    </tbody>
                    <thead>
                      <tr>
                        <th>Disk Index</th>
                        <th>Device ID</th>
                        <th>Size</th>
                        <th>Caption</th>
                        <th>Serial Number</th>
                        <th>Media Type</th>
                        <th>Interace Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      <xsl:for-each select="Computer/DiskDrives/Disk">
                        <tr>
                          <td>
                            <xsl:value-of select="@Index" />
                          </td>
                          <td>
                            <xsl:value-of select="DeviceID" />
                          </td>
                          <td>
                            <xsl:value-of select="Size" />
                          </td>
                          <td>
                            <xsl:value-of select="Caption" />
                          </td>
                          <td>
                            <xsl:value-of select="SerialNumber" />
                          </td>
                          <td>
                            <xsl:value-of select="MediaType" />
                          </td>
                          <td>
                            <xsl:value-of select="InterfaceType" />
                          </td>
                        </tr>
                      </xsl:for-each>
                    </tbody>
                  </table>
                </div>
                <div id="stig-info" class="table-container">
                  <h2>STIG Information</h2>
                  <table id="stig-table">
                    <thead>
                      <tr>
                        <th></th>
                        <th>Start Time</th>
                        <th>Open</th>
                        <th>NF</th>
                        <th>NA</th>
                        <th>NR</th>
                        <th>Eval Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      <xsl:for-each select="Results/Result">
                        <xsl:variable name="STIG" select="@STIG" />
                        <xsl:variable name="NestedID" select="concat('nested-', position())" />
                        <tr>
                          <td>
                            <button class="toggle-btn" onclick="toggleDisplay('{$NestedID}', this)">
                              <span class="arrow"></span>
                              <span class="stig-name">
                                <xsl:value-of select="@STIG" />
                              </span>
                            </button>
                          </td>
                          <td>
                            <xsl:value-of select="@StartTime" />
                          </td>
                          <td>
                            <xsl:value-of select="CAT_I/@Open + CAT_II/@Open + CAT_III/@Open" />
                          </td>
                          <td>
                            <xsl:value-of select="CAT_I/@NotAFinding + CAT_II/@NotAFinding + CAT_III/@NotAFinding" />
                          </td>
                          <td>
                            <xsl:value-of select="CAT_I/@Not_Applicable + CAT_II/@Not_Applicable + CAT_III/@Not_Applicable" />
                          </td>
                          <td>
                            <xsl:value-of select="CAT_I/@Not_Reviewed + CAT_II/@Not_Reviewed + CAT_III/@Not_Reviewed" />
                          </td>
                          <td>
                            <xsl:value-of select="@EvalScore"/>%
                          </td>
                        </tr>
                        <tr id="{$NestedID}" style="display: none">
                          <td colspan="7">
                            <div class="nested-table-container">
                              <div class="group-btn">
                                <button class="filter-btn" data-severity="CAT I" onclick="filterSeverity(this)">CAT I</button>
                                <button class="filter-btn" data-severity="CAT II" onclick="filterSeverity(this)">CAT II</button>
                                <button class="filter-btn" data-severity="CAT III" onclick="filterSeverity(this)">CAT III</button>
                                <input type="text" class="nested-table-search" placeholder="Search..." oninput="filterNested(this)" />
                              </div>
                              <table class="nested-table" id="nested-{$NestedID}">
                                <thead>
                                  <tr>
                                    <th class="sortheading" onclick="sortTable(0, 'nested-{$NestedID}',this)">Severity</th>
                                    <th class="sortheading" onclick="sortTable(1, 'nested-{$NestedID}',this)">Status</th>
                                    <th class="sortheading" onclick="sortTable(2, 'nested-{$NestedID}',this)">Group ID</th>
                                    <th class="sortheading" onclick="sortTable(3, 'nested-{$NestedID}',this)">Rule Title</th>
                                    <th class="sortheading" onclick="sortTable(5, 'nested-{$NestedID}',this)">Comments</th>
                                    <th class="sortheading" onclick="sortTable(5, 'nested-{$NestedID}',this)">Status Change</th>
                                    <th class="sortheading" onclick="sortTable(4, 'nested-{$NestedID}',this)">Override</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  <!-- Consolidated CAT I, II, and III -->
                                  <xsl:for-each select="CAT_I/Vuln | CAT_II/Vuln | CAT_III/Vuln">
                                    <!-- Determine Category Name and CSS Class based on the parent element -->
                                    <xsl:variable name="CategoryName">
                                      <xsl:choose>
                                        <xsl:when test="name(..) = 'CAT_I'">CAT I</xsl:when>
                                        <xsl:when test="name(..) = 'CAT_II'">CAT II</xsl:when>
                                        <xsl:when test="name(..) = 'CAT_III'">CAT III</xsl:when>
                                      </xsl:choose>
                                    </xsl:variable>
                                    <xsl:variable name="Class">
                                      <xsl:choose>
                                        <xsl:when test="@Status='Not_Applicable'">status-NA</xsl:when>
                                        <xsl:when test="@Status='NotAFinding'">status-NF</xsl:when>
                                        <xsl:when test="@Status='Open'">
                                          <xsl:choose>
                                            <xsl:when test="name(..) = 'CAT_I'">status-O_high</xsl:when>
                                            <xsl:when test="name(..) = 'CAT_II'">status-O_med</xsl:when>
                                            <xsl:when test="name(..) = 'CAT_III'">status-O_low</xsl:when>
                                          </xsl:choose>
                                        </xsl:when>
                                        <xsl:otherwise>status-NR</xsl:otherwise>
                                      </xsl:choose>
                                    </xsl:variable>

                                    <tr class="{$Class}">
                                      <!-- Display the dynamic category name -->
                                      <td><xsl:value-of select="$CategoryName" /></td>
                                      <xsl:choose>
                                        <xsl:when test="normalize-space(FindingDetails) != ''">
                                          <td class="CellWithComment">
                                            <u>
                                              <xsl:choose>
                                                <xsl:when test="@Status='Not_Applicable'">NA</xsl:when>
                                                <xsl:when test="@Status='NotAFinding'">NF</xsl:when>
                                                <xsl:when test="@Status='Open'">Open</xsl:when>
                                                <xsl:otherwise>NR</xsl:otherwise>
                                              </xsl:choose>
                                            </u>
                                            <span class="CellComment">
                                              <strong>Finding Details: </strong>
                                              <xsl:value-of select="FindingDetails" />
                                            </span>
                                          </td>
                                        </xsl:when>
                                        <xsl:otherwise>
                                          <td>
                                            <xsl:choose>
                                              <xsl:when test="@Status='Not_Applicable'">NA</xsl:when>
                                              <xsl:when test="@Status='NotAFinding'">NF</xsl:when>
                                              <xsl:when test="@Status='Open'">Open</xsl:when>
                                              <xsl:otherwise>NR</xsl:otherwise>
                                            </xsl:choose>
                                          </td>
                                        </xsl:otherwise>
                                      </xsl:choose>
                                      <xsl:choose>
                                        <xsl:when test="@LegacyIDs != ''">
                                          <td class="CellWithComment">
                                            <u>
                                              <xsl:value-of select="@ID" />
                                            </u>
                                            <span class="CellComment">
                                              <strong>Legacy IDs: </strong>
                                              <xsl:value-of select="@LegacyIDs" />
                                            </span>
                                          </td>
                                        </xsl:when>
                                        <xsl:otherwise>
                                          <td>
                                            <xsl:value-of select="@ID" />
                                          </td>
                                        </xsl:otherwise>
                                      </xsl:choose>
                                      <td>
                                        <xsl:value-of select="@RuleTitle" />
                                      </td>
                                      <xsl:choose>
                                        <xsl:when test="normalize-space(AnswerFile) != ''">
                                          <td class="CellWithComment">
                                            <u>True</u>
                                            <span class="CellComment">
                                              <strong>Comments: </strong>
                                              <xsl:value-of select="AnswerFile" />
                                            </span>
                                          </td>
                                        </xsl:when>
                                        <xsl:otherwise>
                                          <td />
                                        </xsl:otherwise>
                                      </xsl:choose>
                                      <xsl:choose>
                                        <xsl:when test="AnswerFile/@StatusChanged != ''">
                                          <td class="CellWithComment">
                                            <u>
                                              <xsl:value-of select="AnswerFile/@StatusChanged" />
                                            </u>
                                            <span class="CellComment">
                                              <strong>Pre-Answer File Status: </strong>
                                              <xsl:value-of select="AnswerFile/@PreAFStatus" />
                                            </span>
                                          </td>
                                        </xsl:when>
                                        <xsl:otherwise>
                                          <td />
                                        </xsl:otherwise>
                                      </xsl:choose>
                                      <xsl:choose>
                                        <xsl:when test="Override/@Overridden != ''">
                                          <td class="CellWithComment">
                                            <u>
                                              <xsl:value-of select="Override/@Overridden" />
                                            </u>
                                            <span class="CellComment">
                                              <strong>Previous Severity: </strong>
                                              <xsl:value-of select="Override/@PreviousSeverity" />
                                              <br />
                                              <strong>Justification: </strong>
                                              <xsl:value-of select="Override" />
                                            </span>
                                          </td>
                                        </xsl:when>
                                        <xsl:otherwise>
                                          <td />
                                        </xsl:otherwise>
                                      </xsl:choose>
                                    </tr>
                                  </xsl:for-each>
                                </tbody>
                              </table>
                            </div>
                          </td>
                        </tr>
                      </xsl:for-each>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            <script>
              var riskScore =
              <xsl:value-of select="number(Computer/Score/WeightedAvg)"/>;
              var nfPercentage =
              <xsl:choose>
                <xsl:when test ="(sum(Results/Result/CAT_I/@Total) + sum(Results/Result/CAT_II/@Total) + sum(Results/Result/CAT_III/@Total)) > 0">
                  <xsl:value-of select="format-number(
                      ((sum(Results/Result/CAT_I/@NotAFinding) + sum(Results/Result/CAT_I/@Not_Applicable) +
                      sum(Results/Result/CAT_II/@NotAFinding) + sum(Results/Result/CAT_II/@Not_Applicable) +
                      sum(Results/Result/CAT_III/@NotAFinding) + sum(Results/Result/CAT_III/@Not_Applicable)) div
                      (sum(Results/Result/CAT_I/@Total) + sum(Results/Result/CAT_II/@Total) + sum(Results/Result/CAT_III/@Total))) * 100,
                      '0.00')"/>
                </xsl:when>
                <xsl:otherwise>0.0</xsl:otherwise>
              </xsl:choose>;

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

              //toggle table visibility
              function change(table_value) {
                var x = document.getElementById(table_value);
                var rows = document.getElementById(table_value).getElementsByTagName("tbody");

                if (x.style.display === "none") {
                  x.style.display = "table";
                } else {
                  x.style.display = "none";
                }
              }

              //Filter main table based on search input
              function filterTable(input,table_value) {
                var input, filter, table, tr, td, i, txtValue;
                input = document.getElementById(input);
                filter = input.value.toUpperCase();
                table = document.getElementById(table_value);
                tr = table.getElementsByTagName("tr");

                for (i = 0; i &lt; tr.length; i++) {
                  var allTDs = tr[i].getElementsByTagName("td");
                  for (index = 0; index &lt; allTDs.length; index++) {
                    txtValue = allTDs[index].textContent || allTDs[index].innerText;
                    if (txtValue.toUpperCase().indexOf(filter) &gt; -1) {
                      tr[i].style.display = "";
                      break;
                    } else {
                      tr[i].style.display = "none";
                    }
                  }
                }
              }

              var chartSlices = {};
              var chartDataMap = {};

              const chartData = [
                {
                  id: "pieChartOverall",
                  data: [
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@Open))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_II/@Open))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_III/@Open))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@NotAFinding) + sum(Results/Result/CAT_II/@NotAFinding) + sum(Results/Result/CAT_III/@NotAFinding))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@Not_Reviewed) + sum(Results/Result/CAT_II/@Not_Reviewed) + sum(Results/Result/CAT_III/@Not_Reviewed))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@Not_Applicable) + sum(Results/Result/CAT_II/@Not_Applicable) + sum(Results/Result/CAT_III/@Not_Applicable))" />,
                  ],
                  labels: ["Open: CAT I", "Open: CAT II", "Open: CAT III", "NF", "NR", "NA"],
                  colors: ["var(--o-cat1-bg)","var(--o-cat2-bg)","var(--o-cat3-bg)", "var(--nf-bg)", "var(--nr-bg)", "var(--na-bg)"],
                  isDonut: true
                },
                {
                  id: "barChart1",
                  type: "bar",
                  data: [
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@Open))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@NotAFinding))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@Not_Reviewed))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_I/@Not_Applicable))" />,
                  ],
                  labels: ["Open", "NF", "NR", "NA"],
                  colors: ["var(--o-cat1-bg)", "var(--nf-bg)", "var(--nr-bg)", "var(--na-bg)"]
                },
                {
                  id: "barChart2",
                  type: "bar",
                  data: [
              <xsl:value-of select="number(sum(Results/Result/CAT_II/@Open))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_II/@NotAFinding))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_II/@Not_Reviewed))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_II/@Not_Applicable))" />,
                  ],
                  labels: ["Open", "NF", "NR", "NA"],
                  colors: ["var(--o-cat2-bg)", "var(--nf-bg)", "var(--nr-bg)", "var(--na-bg)"]
                },
                {
                  id: "barChart3",
                  type: "bar",
                  data: [
              <xsl:value-of select="number(sum(Results/Result/CAT_III/@Open))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_III/@NotAFinding))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_III/@Not_Reviewed))" />,
              <xsl:value-of select="number(sum(Results/Result/CAT_III/@Not_Applicable))" />,
                  ],
                  labels: ["Open", "NF", "NR", "NA"],
                  colors: ["var(--o-cat3-bg)", "var(--nf-bg)", "var(--nr-bg)", "var(--na-bg)"]
                }
              ];
              <![CDATA[
                var topbutton = document.getElementById("topbtn");

                //Toggle nested table rows and reset filter/sorting when closing
                function toggleDisplay(id, btn) {
                  const element = document.getElementById(id) || document.querySelector("#" + id.replace(/-table$/, ""));
                  if (!element) return;
                  const isCollapsed = (element.style.display === "none" || element.style.display === "");

                  //Toggle visibility
                  element.style.display = isCollapsed ? "table-row" : "none";

                  //Reset filter option
                  if (!isCollapsed) {
                    const nestedContainer = element.querySelector(".nested-table-container") || element.closest(".nested-table-container");
                    const nestedTable = element.querySelector(".nested-table") || document.querySelector("#nested-nested-1, #nested-nested-2");
                    document.querySelectorAll("#nested-nested-1 tbody tr, #nested-nested-2 tbody tr").forEach(row => row.style.display = "");
                    document.querySelectorAll(".filter-btn").forEach(btn => btn.classList.remove("active"));
                    const search = document.querySelector('.nested-table-search');

                    if (search) search.value = '';
                    element.querySelectorAll("th.sortheading").forEach(th => th.classList.remove('asc', 'desc'));

                    if (typeof lastSorted !== 'undefined') {
                      lastSorted = { table: null, column: null, direction: null };
                    }
                  }

                  // Toggle button expanded state for arrows
                  if (btn) {
                    btn.classList.toggle("expanded", isCollapsed);
                  }
                }

                //Filter nested table rows based on search input
                function filterNested(input) {
                  const filter = input.value.toUpperCase();

                  //Find the parent container and table elements
                  const nestedContainer = input.closest(".nested-table-container");
                  if (!nestedContainer) return;
                  const table = nestedContainer.querySelector("table");
                  const tbody = table.querySelector("tbody");
                  const rows = tbody.getElementsByTagName("tr");
                  let found = 0;

                  // Remove result message if it a a match exists
                  const oldMsg = nestedContainer.querySelector(".no-results");
                  if (oldMsg) oldMsg.remove();

                  // Check if a severity filter is active
                  const activeBtn = nestedContainer.querySelector('.filter-btn.active');
                  const activeSeverity = activeBtn ? activeBtn.dataset.severity : null;

                  //Loop through to find a match
                  for (let i = 0; i < rows.length; i++) {
                    const rowText = rows[i].textContent.toUpperCase();
                    const matchesSearch = filter === "" || rowText.includes(filter);
                    const matchesSeverity = !activeSeverity || rows[i].children[0].textContent.trim() === activeSeverity;

                    //Show the row if it contains the search text
                    if (matchesSearch && matchesSeverity) {
                      rows[i].style.display = "";
                      found++;
                    } else {
                      rows[i].style.display = "none";
                    }
                  }

                  // when nothing matches, display "Result not found"
                  if (found === 0) {
                    const msg = document.createElement("div");
                    msg.className = "no-results";
                    msg.textContent = "Result not found";
                    nestedContainer.appendChild(msg);
                  }
                }

                function getCellSortText(td){
                  if (!td) return '';
                  var clone = td.cloneNode(true);
                  var comment = clone.querySelector('.CellComment');
                  if (comment) comment.remove();
                  return clone.textContent.trim().toLowerCase();
                }

                //Store the original row order
                let originalRows = {};

                //Save the original row order before sorting
                function saveOriginalOrder(tableId) {
                  if (!originalRows[tableId]) {
                    const table = document.getElementById(tableId);
                    //Make a clone of all rows to have original order
                    originalRows[tableId] = Array.from(table.tBodies[0].rows).map(row => row.cloneNode(true));
                  }
                }

                let lastSorted = { table: null, column: null, direction: null };

                //Sort table column from asc to desc back to its orginal order
                function sortTable(n, tableId, headerEl) {
                  saveOriginalOrder(tableId);
                  const table = document.getElementById(tableId);
                  const tbody = table.tBodies[0];
                  let rows = Array.from(tbody.rows);

                  let dir;
                  if (lastSorted.table === tableId && lastSorted.column === n) {
                    if (lastSorted.direction === 'asc') dir = 'desc';
                    else if (lastSorted.direction === 'desc') {
                      tbody.innerHTML = "";
                      originalRows[tableId].forEach(row => tbody.appendChild(row.cloneNode(true)));
                      headerEl.classList.remove('asc', 'desc');
                      lastSorted = { table: null, column: null, direction: null };
                      var activeBtn = table.closest('.nested-table-container')
                        ?.querySelector('.filter-btn.active');
                      if (activeBtn) {
                        var severity = activeBtn.dataset.severity;
                        Array.from(tbody.rows).forEach(function(row) {
                          var rowSeverity = row.children[0].textContent.trim();
                          row.style.display = (rowSeverity === severity) ? "" : "none";
                        });
                      }
                      return;
                    } else {
                      dir = 'asc';
                    }
                  } else {
                    dir = 'asc';
                  }

                  // Sort rows
                  rows.sort((a, b) => {
                    let x = getCellSortText(a.getElementsByTagName("TD")[n])
                    let y = getCellSortText(b.getElementsByTagName("TD")[n]);
                    let xn = parseFloat(x.replace(/[^0-9.\-]/g, ""));
                    let yn = parseFloat(y.replace(/[^0-9.\-]/g, ""));
                    if (!isNaN(xn) && !isNaN(yn)) { x = xn; y = yn; }
                    return (dir === 'asc') ? (x > y ? 1 : -1) : (x < y ? 1 : -1);
                  });

                  // Re-append rows
                  tbody.innerHTML = "";
                  rows.forEach(row => tbody.appendChild(row));

                  // Update header classes
                  table.querySelectorAll("th.sortheading").forEach(th => th.classList.remove('asc', 'desc'));
                  headerEl.classList.add(dir);

                  // Save last sorted column
                  lastSorted = { table: tableId, column: n, direction: dir };
                }

                var detailChartsInitialized = false;

                function filterSeverity(btn) {
                  const severity = btn.dataset.severity;
                  const container = btn.closest(".nested-table-container");
                  const table = container.querySelector(".nested-table");
                  const rows = table.querySelectorAll("tbody tr");

                  if (btn.classList.contains("active")) {
                    btn.classList.remove("active");
                    rows.forEach(row => row.style.display = "");
                    return;
                  }

                  btn.closest(".group-btn")
                    .querySelectorAll(".filter-btn")
                    .forEach(b => b.classList.remove("active"));
                  btn.classList.add("active");
                  rows.forEach(row => {
                    const rowSeverity = row.children[0].textContent.trim();
                    row.style.display = (rowSeverity === severity) ? "" : "none";
                  });
                }
                //Store animation state for each chart
                var chartAnimationState = {};

                //Draw pie chart using canvas with highlight function
                function drawPieChart(canvasId, data, colors, highlightIndex = -1, sliceRadii = null) {
                  var canvas = document.getElementById(canvasId);
                  if (!canvas) return;
                  var ctx = canvas.getContext('2d');

                  var validData = data.filter(v => typeof v === 'number' && !isNaN(v));
                  var total = validData.reduce((sum, val) => sum + val, 0);
                  ctx.clearRect(0, 0, canvas.width, canvas.height);
                  var baseRadius = Math.min(canvas.width, canvas.height) / 2 - 10;
                  var isDonut = chartDataMap[canvasId] && chartDataMap[canvasId].isDonut;
                  var innerRadius = isDonut ? Math.min(canvas.width, canvas.height) / 2 * 0.5 : 0;

                  if (total === 0) {
                    ctx.beginPath();
                    ctx.arc(canvas.width / 2, canvas.height / 2, Math.min(canvas.width, canvas.height) / 2 - 10, 0, 2 * Math.PI);
                    ctx.closePath();
                    ctx.fillStyle = "rgba(200,200,200,0.15)";
                    ctx.fill();
                    ctx.fillStyle = "#999";
                    ctx.font = "14px Arial";
                    ctx.textAlign = "center";
                    ctx.fillText("N/A", canvas.width / 2, canvas.height / 2);
                    return;
                  }

                  var startAngle = 0;
                  var centerX = canvas.width / 2;
                  var centerY = canvas.height / 2;
                  var baseRadius = Math.min(canvas.width, canvas.height) / 2 - 10;
                  var slices = [];


                  if (!sliceRadii) {
                    sliceRadii = data.map(() => baseRadius);
                  }

                  var sliceIndex = 0;
                  data.forEach((value, i) => {
                    if (typeof value !== 'number' || isNaN(value) || value <= 0) return;

                    var sliceAngle = (value / total) * 2 * Math.PI;
                    var endAngle = startAngle + sliceAngle;
                    var radius = sliceRadii[i] || baseRadius;

                    ctx.beginPath();
                    if (isDonut) {
                      ctx.arc(centerX, centerY, radius, startAngle, endAngle);
                      ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
                    } else {
                      ctx.moveTo(centerX, centerY);
                      ctx.arc(centerX, centerY, radius, startAngle, endAngle);
                    }
                    ctx.closePath();
                    ctx.fillStyle = (i === highlightIndex) ? shadeColor(colors[i], -7) : colors[i];
                    ctx.fill();

                    slices.push({ start: startAngle, end: endAngle, label: chartDataMap[canvasId].labels[i], value: value, index: i });
                    startAngle = endAngle;
                    sliceIndex++;
                  });

                  if (isDonut) {
                    ctx.font = "12px Arial";
                    ctx.fillStyle = "#666";
                    ctx.fillText("Evaluate-STIG Score", centerX, centerY + 14);
                    ctx.fillStyle = "#333";
                    ctx.font = "bold 24px Arial";
                    ctx.textAlign = "center";
                    ctx.textBaseline = "middle";
                    ctx.fillText(nfPercentage.toString() + " %", centerX, centerY - 10);
                  }

                  chartSlices[canvasId] = slices;
                }

                // Draw a horizontal stacked bar chart
                function drawStackedBarChart(chartId, data, colors, labels) {
                  var container = document.getElementById(chartId);
                  if (!container) return;

                  var total = data.reduce((sum, val) => sum + (typeof val === 'number' && !isNaN(val) ? val : 0), 0);

                  // Clear existing content
                  container.innerHTML = '';

                  // Handle empty data
                  if (total === 0) {
                    container.innerHTML = '<div class="stacked-bar-wrapper"><div style="width:100%;text-align:center;color:#999;font-size:12px;line-height:32px;">No Data</div></div>';
                    return;
                  }

                  // Create bar wrapper
                  var wrapper = document.createElement('div');
                  wrapper.className = 'stacked-bar-wrapper';

                  // Create segments
                  data.forEach((value, i) => {
                    if (typeof value !== 'number' || isNaN(value) || value <= 0) return;

                    var percentage = (value / total) * 100;
                    var segment = document.createElement('div');
                    segment.className = 'bar-segment';
                    segment.style.flex = percentage.toString();
                    segment.style.backgroundColor = colors[i];
                    segment.setAttribute('data-label', labels[i]);
                    segment.setAttribute('data-value', value);
                    segment.setAttribute('data-percentage', percentage.toFixed(1));

                    // Add value label inside segment if it's wide enough
                    var span = document.createElement('span');
                    span.textContent = value;
                    segment.appendChild(span);

                    // Tooltip on hover
                    segment.addEventListener('mouseenter', function (e) {
                      showBarTooltip(e, labels[i], value, percentage.toFixed(1));
                    });
                    segment.addEventListener('mousemove', function (e) {
                      moveBarTooltip(e);
                    });
                    segment.addEventListener('mouseleave', function () {
                      hideBarTooltip();
                    });

                      wrapper.appendChild(segment);
                  });

                  container.appendChild(wrapper);
                }

                // Update legend for bar charts
                function updateBarLegend(chartId) {
                  var legendId = 'legend-' + chartId;
                  var legendEl = document.getElementById(legendId);
                  if (!legendEl) return;

                  var chart = chartDataMap[chartId];
                  if (!chart) return;

                  legendEl.innerHTML = '';

                  chart.labels.forEach((label, i) => {
                    var value = chart.data[i];
                    var li = document.createElement('li');
                    li.innerHTML = '<span class="legend-color" style="background-color: ' + chart.colors[i] + '"></span>' +
                      label + ' <span class="legend-count">(' + value + ')</span>';
                    legendEl.appendChild(li);
                  });
                }

                //Darken or lighten the chart
                function shadeColor(color, percent) {
                  var num = parseInt(color.slice(1), 16),
                    amt = Math.round(2.55 * percent),
                    R = (num >> 16) + amt,
                    G = (num >> 8 & 0x00FF) + amt,
                    B = (num & 0x0000FF) + amt;
                  return "#" + (
                    0x1000000 +
                    (R < 255 ? (R < 0 ? 0 : R) : 255) * 0x10000 +
                    (G < 255 ? (G < 0 ? 0 : G) : 255) * 0x100 +
                    (B < 255 ? (B < 0 ? 0 : B) : 255)
                  ).toString(16).slice(1);
                }

                //Attach on hover function to pir chart with data tooltip and slicing animation
                function attachChartHover(canvasId) {
                  var canvas = document.getElementById(canvasId);
                  if (!canvas) return;
                  var tooltip = document.createElement("div");
                  tooltip.className = "chart-tooltip";
                  document.body.appendChild(tooltip);

                  let currentHighlight = -1;
                  const RADIUS_BOOST = 3;
                  const ANIMATION_DURATION = 150;

                  var baseRadius = Math.min(canvas.width, canvas.height) / 2 - 10;
                  var isDonut = chartDataMap[canvasId] && chartDataMap[canvasId].isDonut;
                  var innerRadius = isDonut ? Math.min(canvas.width, canvas.height) / 2 * 0.5 : 0;
                  var data = chartDataMap[canvasId].data;

                  // Initialize animation state for the charts
                  chartAnimationState[canvasId] = {
                    currentRadii: data.map(() => baseRadius),
                    targetRadii: data.map(() => baseRadius),
                    animating: false,
                    animationStart: 0
                  };

                  //Hide the chart tooltip
                  function hideTooltip() {
                    tooltip.style.opacity = "0";
                    tooltip.style.transform = "scale(0.8) translateY(-10px)";
                  }

                  function animateChart(timestamp) {
                    var state = chartAnimationState[canvasId];
                    if (!state.animating) return;

                    if (!state.animationStart) {
                      state.animationStart = timestamp;
                    }

                    var elapsed = timestamp - state.animationStart;
                    var progress = Math.min(elapsed / ANIMATION_DURATION, 1);
                    var easeProgress = 1 - Math.pow(1 - progress, 3);
                    var newRadii = state.currentRadii.map((startRadius, i) => {
                      var targetRadius = state.targetRadii[i];
                      return startRadius + (targetRadius - startRadius) * easeProgress;
                    });

                    drawPieChart(canvasId, chartDataMap[canvasId].data, chartDataMap[canvasId].colors, currentHighlight, newRadii);

                    if (progress < 1) {
                      requestAnimationFrame(animateChart);
                    } else {
                      state.currentRadii = [...state.targetRadii];
                      state.animating = false;
                      state.animationStart = 0;
                    }
                  }

                  //Set which slice is to be highlighted
                  function setHighlight(index) {
                    if (currentHighlight === index) return;

                    var state = chartAnimationState[canvasId];
                    currentHighlight = index;

                    //Set radii as starting point for animation
                    state.currentRadii = [...state.currentRadii];
                    state.targetRadii = data.map((_, i) => {
                      return (i === index) ? baseRadius + RADIUS_BOOST : baseRadius;
                    });

                    //Start animation is already running
                    state.animationStart = 0;
                    if (!state.animating) {
                      state.animating = true;
                      requestAnimationFrame(animateChart);
                    }
                  }

                  function resetHighlight() {
                    if (currentHighlight === -1) return;
                    setHighlight(-1);
                  }

                  canvas.addEventListener("mousemove", function (e) {
                    var rect = canvas.getBoundingClientRect();
                    var scaleX = canvas.width / rect.width;
                    var scaleY = canvas.height / rect.height;

                    // Calculate position to canvas center
                    var x = (e.clientX - rect.left) * scaleX - canvas.width / 2;
                    var y = (e.clientY - rect.top) * scaleY - canvas.height / 2;

                    var dist = Math.sqrt(x * x + y * y);
                    var maxRadius = baseRadius + RADIUS_BOOST + 2;

                    var dist = Math.sqrt(x * x + y * y);
                    var maxRadius = baseRadius + RADIUS_BOOST + 2;

                    // Check if outside the pie chart area
                    if (dist > maxRadius || dist < innerRadius) {
                      hideTooltip();
                      resetHighlight();
                      return;
                    }

                    var angle = Math.atan2(y, x);
                    if (angle < 0) angle += 2 * Math.PI;

                    var slices = chartSlices[canvasId] || [];
                    var found = null;
                    for (var i = 0; i < slices.length; i++) {
                      var s = slices[i];
                      if (s.start <= s.end) {
                        if (angle >= s.start && angle < s.end) {
                          found = s;
                          break;
                        }
                      } else {
                        if (angle >= s.start || angle < s.end) {
                          found = s;
                          break;
                        }
                      }
                    }
                    //If slice is found the highlight and data tooltip will show
                    if (found) {
                      tooltip.innerHTML = `<strong>${found.label}</strong>: ${found.value}`;
                      tooltip.style.left = e.pageX + 12 + "px";
                      tooltip.style.top = e.pageY + 12 + "px";
                      tooltip.style.opacity = "1";
                      tooltip.style.transform = "scale(1) translateY(0)";

                      //Expand the hovered slice
                      setHighlight(found.index);
                    } else {
                      hideTooltip();
                      resetHighlight();
                    }
                  });

                  //Hide the tooltip when mouse move from canvas
                  canvas.addEventListener("mouseleave", function () {
                    hideTooltip();
                    resetHighlight();
                  });
                }

                function updateLegend(canvasId) {
                  const legendId = 'legend-' + canvasId;
                  const legendEl = document.getElementById(legendId);
                  if (!legendEl) return;

                  const chart = chartDataMap[canvasId];
                  legendEl.innerHTML = '';

                  //Create legend item for each data point
                  chart.labels.forEach((label, i) => {
                    const value = chart.data[i];
                    const li = document.createElement('li');

                    //Add color swatch, label, adn CAT count
                    li.innerHTML = `
                      <span class="legend-color" style="background-color: ${chart.colors[i]}"></span>
                      ${label}
                      <span class="legend-count">(${value})</span>
                    `;
                    legendEl.appendChild(li);
                  });
                }

                //Initialize all charts with data, legend and hover effect
                function initAnimatedPieCharts(chartData) {
                  // A helper to get the computed value of a CSS variable
                  function getCssVariableValue(varName) {
                    // Extracts '--variable-name' from 'var(--variable-name)'
                    const cssVar = varName.match(/--[a-zA-Z0-9_-]+/)[0];
                    if (cssVar) {
                      return getComputedStyle(document.documentElement).getPropertyValue(cssVar).trim();
                    }
                    return varName; // Fallback to the original string if parsing fails
                  }

                  // Loop through chart data to store and initialize ALL charts
                  chartData.forEach(chart => {
                    // Resolve CSS variable colors to their actual values
                    const resolvedColors = chart.colors.map(color => {
                      if (color.startsWith('var(')) {
                        return getCssVariableValue(color);
                      }
                      return color;
                    });

                    // Create a new chart object with the resolved colors
                    const resolvedChart = { ...chart, colors: resolvedColors };
                    chartDataMap[chart.id] = resolvedChart;

                    // Check if it's a bar chart or pie chart and draw accordingly
                    if (chart.type === 'bar') {
                      drawStackedBarChart(chart.id, resolvedChart.data, resolvedChart.colors, resolvedChart.labels);
                      updateBarLegend(chart.id);
                    } else {
                      drawPieChart(chart.id, resolvedChart.data, resolvedChart.colors);
                      updateLegend(chart.id);
                      attachChartHover(chart.id);
                    }
                  });
                }

                function applyDefaultSort() {
                  // Find all nested tables
                  const nestedTables = document.querySelectorAll('.nested-table');

                  nestedTables.forEach(table => {
                    const tableId = table.id;
                    if (!tableId) return;

                    sortTableDefault(2, tableId);
                  });
                }

                // Function to have sort GROUPID as the default sort
                function sortTableDefault(n, tableId) {
                  const table = document.getElementById(tableId);
                  if (!table) return;

                  const tbody = table.tBodies[0];
                  let rows = Array.from(tbody.rows);

                  // Sort rows ascending by the selected column
                  rows.sort((a, b) => {
                    let x = getCellSortText(a.getElementsByTagName("TD")[n]);
                    let y = getCellSortText(b.getElementsByTagName("TD")[n]);

                    // Try parsing numbers for the sorting order
                    let xn = parseFloat(x.replace(/[^0-9.\-]/g, ""));
                    let yn = parseFloat(y.replace(/[^0-9.\-]/g, ""));
                    if (!isNaN(xn) && !isNaN(yn)) { x = xn; y = yn; }

                    //return the sort in Desc or Asc order based on '<' direction
                    return (x < y ? 1 : -1);
                  });

                  // This clears the table and re-append sorted rows
                  tbody.innerHTML = "";
                  rows.forEach(row => tbody.appendChild(row));

                  // Save original order after default sort
                  originalRows[tableId] = Array.from(tbody.rows).map(row => row.cloneNode(true));
                }

                (function () {
                  document.addEventListener('mouseenter', function(e) {
                    var cell = e.target.closest('.CellWithComment');
                    if (!cell) return;
                    var tooltip =  cell.querySelector('.CellComment');
                    if (!tooltip) return;
                    var rect = cell.getBoundingClientRect();
                    var OFFSET = 8;
                    var PADDING = 8;

                    // Measure tooltip dimensions while hidden
                    tooltip.style.display = 'block';
                    var ttHeight = tooltip.offsetHeight;
                    var ttWidth = tooltip.offsetWidth;

                    // Prefer showing above; flip below if not enough room
                    var top = rect.top - ttHeight - OFFSET;
                    if (top < PADDING) {
                      top = rect.bottom + OFFSET;
                    }

                    // Center horizontally over the cell, clamped to viewport
                    var left = rect.left + rect.width / 2 - ttWidth / 2;
                    left = Math.max(PADDING, Math.min(left, window.innerWidth - ttWidth - PADDING));

                    tooltip.style.top = top + 'px';
                    tooltip.style.left = left + 'px';
                    tooltip.style.visibility = 'visible';
                    tooltip.style.opacity = '1';
                  }, true);

                  document.addEventListener('mouseleave', function(e) {
                    var cell = e.target.closest('.CellWithComment');
                    if (!cell) return;
                    var tooltip = cell.querySelector('.CellComment');
                    if (!tooltip) return;

                    tooltip.style.visibility = 'hidden';
                    tooltip.style.opacity = '0';
                  }, true);
                })();

                document.addEventListener('DOMContentLoaded', function () {
                  const riskLevelSpan = document.querySelector('.risk-level');
                  if (!riskLevelSpan) return;

                  //Set the tooltip for risk score percentage
                  if (riskLevelSpan) {
                    riskLevelSpan.setAttribute('data-tooltip', 'Risk Score: ' + riskScore + "%");
                  }

                  //Remove any existing classes once the risk level is found
                  const riskText = riskLevelSpan.textContent.trim().toLowerCase();
                  riskLevelSpan.classList.remove('risk-very-high', 'risk-high', 'risk-moderate', 'risk-low', 'risk-very-low');

                  //Add color class based on risk level (refer to CSS variable if colors)
                  if (riskText.includes("very high")) {
                    riskLevelSpan.classList.add("risk-very-high");
                  } else if (riskText.includes("high")) {
                    riskLevelSpan.classList.add("risk-high");
                  } else if (riskText.includes("moderate")) {
                    riskLevelSpan.classList.add("risk-moderate");
                  } else if (riskText.includes("low")) {
                    riskLevelSpan.classList.add("risk-low");
                  } else if (riskText.includes("very low")) {
                    riskLevelSpan.classList.add("risk-very-low");
                  }

                  initAnimatedPieCharts(chartData);

                  applyDefaultSort();

                  document.fonts.ready.then(() => {
                    initAnimatedPieCharts(chartData);
                  });
                });
              ]]>
            </script>
          </div>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>