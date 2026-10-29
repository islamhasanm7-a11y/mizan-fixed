"""
MizanPro ERP & CPA Suite - Calendar-Based Transaction & Compliance Anomaly Heatmap Service
خدمة الخريطة الحرارية التقويمية لتحليل كثافة العمليات المالية ورصد الشذوذ والتنبيهات الرقابية
"""

import json
from collections import defaultdict
from datetime import datetime, date, timedelta
from typing import Any, Dict, List, Optional


class HeatmapService:
    """محرك تجميع وتحليل البيانات للخريطة الحرارية التقويمية ورصد الشذوذ والتنبيهات"""

    @classmethod
    def aggregate_calendar_heatmap_data(
        cls,
        db_session: Any,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        year: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        تجميع كافة سجلات التدقيق اليومية وحساب كثافة المعاملات والأحجام المالية ورصد الشذوذ والأنماط المشبوهة
        """
        from models import AuditLog

        query = db_session.query(AuditLog)

        # تحديد النطاق الزمني للتقويم
        today_d = date.today()
        if year:
            eff_start = date(year, 1, 1)
            eff_end = date(year, 12, 31)
        else:
            eff_end = end_date or today_d
            eff_start = start_date or (eff_end - timedelta(days=365))

        query = query.filter(AuditLog.timestamp >= datetime.combine(eff_start, datetime.min.time()))
        query = query.filter(AuditLog.timestamp <= datetime.combine(eff_end, datetime.max.time()))

        logs = query.order_by(AuditLog.timestamp.asc()).all()

        daily_map = defaultdict(lambda: {
            "tx_count": 0,
            "financial_volume_sar": 0.0,
            "modifications_count": 0,
            "anomalies_count": 0,
            "anomaly_reasons": set(),
            "users": set(),
            "actions": set(),
            "has_broken_hash": False,
            "after_hours_count": 0,
        })

        total_volume_sar = 0.0
        total_tx = len(logs)

        # حساب المتوسط اليومي لتقييم الشذوذ
        all_amounts = [float(getattr(l, "financial_amount", 0.0) or 0.0) for l in logs if float(getattr(l, "financial_amount", 0.0) or 0.0) > 0]
        avg_amount = (sum(all_amounts) / len(all_amounts)) if all_amounts else 5000.0

        for log in logs:
            ts = getattr(log, "timestamp", None)
            if not isinstance(ts, datetime):
                continue

            day_key = ts.strftime("%Y-%m-%d")
            amt = float(getattr(log, "financial_amount", 0.0) or 0.0)
            act = str(getattr(log, "action", "") or "").upper()
            tbl = str(getattr(log, "table_name", "") or "").lower()
            user_lbl = str(getattr(log, "performed_by", "") or getattr(log, "user_id", "") or "مستخدم").split("(")[0].strip()

            daily_map[day_key]["tx_count"] += 1
            daily_map[day_key]["financial_volume_sar"] += amt
            daily_map[day_key]["users"].add(user_lbl)
            daily_map[day_key]["actions"].add(act)

            total_volume_sar += amt

            # رصد التعديل أو العكس
            if any(k in act for k in ["MODIFY", "REVERSE", "UPDATE", "DELETE"]):
                daily_map[day_key]["modifications_count"] += 1

            # رصد الشذوذ في خروج الأوقات (بعد ساعات العمل الرسمية 8م - 6ص)
            if ts.hour >= 20 or ts.hour < 6:
                daily_map[day_key]["after_hours_count"] += 1

            # رصد خلل البصمة SHA-256
            if not getattr(log, "is_hash_valid", True):
                daily_map[day_key]["has_broken_hash"] = True

        # تحليل وتقييم مستوى الكثافة والأنومالي لكل يوم
        calendar_days = {}
        anomaly_days_count = 0
        peak_day_key = None
        peak_tx_count = 0
        peak_vol_key = None
        peak_vol_sar = 0.0

        for day_key, data in daily_map.items():
            tx_cnt = data["tx_count"]
            vol_sar = data["financial_volume_sar"]
            mods_cnt = data["modifications_count"]
            reasons = list(data["anomaly_reasons"])

            # رصد شذوذ الحجم المالي (تجاوز 4 أضعاف المتوسط)
            if vol_sar > (avg_amount * 4) and vol_sar > 25000.0:
                reasons.append(f"⚠️ حجم مالي استثنائي ({vol_sar:,.2f} ريال) يتجاوز المتوسط اليومي")
                data["anomalies_count"] += 1

            # رصد شذوذ التعديلات العالية (تجاوز 3 عمليات تعديل في يوم واحد)
            if mods_cnt >= 3:
                reasons.append(f"🔄 كثرة عمليات التعديل وإلغاء المستندات ({mods_cnt} عمليات)")
                data["anomalies_count"] += 1

            # رصد العمليات خارج أوقات العمل
            if data["after_hours_count"] >= 2:
                reasons.append(f"🌙 تنفيذ {data['after_hours_count']} عمليات متكررة خارج أوقات الدوام الرسمي")
                data["anomalies_count"] += 1

            # رصد خلل البصمة
            if data["has_broken_hash"]:
                reasons.append("❌ رصد تنبيه أمني: عدم تطابق في بصمة SHA-256 التشفيرية")
                data["anomalies_count"] += 2

            is_anomaly = (data["anomalies_count"] > 0)
            if is_anomaly:
                anomaly_days_count += 1

            # تحديث ذروة الأيام
            if tx_cnt > peak_tx_count:
                peak_tx_count = tx_cnt
                peak_day_key = day_key
            if vol_sar > peak_vol_sar:
                peak_vol_sar = vol_sar
                peak_vol_key = day_key

            # تحديد مستوى الكثافة (Intensity Index: 0-4)
            if is_anomaly or data["anomalies_count"] > 0:
                intensity = 4  # مستوى تنبيه عالي (Red)
            elif tx_cnt >= 15 or vol_sar >= 50000:
                intensity = 3  # نشاط مرتفع جداً (Amber/Orange)
            elif tx_cnt >= 6 or vol_sar >= 15000:
                intensity = 2  # نشاط متوسط (Blue)
            elif tx_cnt >= 1:
                intensity = 1  # نشاط منخفض (Light Blue)
            else:
                intensity = 0  # بدون حركات (Dark Slate)

            color_map = {
                0: "#1e293b",
                1: "#0284c7",
                2: "#0369a1",
                3: "#f59e0b",
                4: "#ef4444",
            }

            calendar_days[day_key] = {
                "date": day_key,
                "tx_count": tx_cnt,
                "financial_volume_sar": round(vol_sar, 2),
                "modifications_count": mods_cnt,
                "anomalies_count": data["anomalies_count"],
                "is_anomaly": is_anomaly,
                "anomaly_reasons": reasons,
                "users_count": len(data["users"]),
                "intensity": intensity,
                "color": color_map[intensity],
            }

        return {
            "calendar_days": calendar_days,
            "start_date": eff_start.strftime("%Y-%m-%d"),
            "end_date": eff_end.strftime("%Y-%m-%d"),
            "metrics": {
                "total_transactions": total_tx,
                "total_volume_sar": round(total_volume_sar, 2),
                "monitored_days_count": len(calendar_days),
                "anomaly_days_count": anomaly_days_count,
                "peak_tx_day": peak_day_key or "—",
                "peak_tx_count": peak_tx_count,
                "peak_vol_day": peak_vol_key or "—",
                "peak_vol_sar": round(peak_vol_sar, 2),
            },
        }

    @classmethod
    def generate_heatmap_html(cls, heatmap_data: Dict[str, Any]) -> str:
        """
        توليد مستند HTML تفاعلي يعرض خريطة الحرارة التقويمية (Calendar Matrix Heatmap) ببطاقات تفاعلية وتلميحات
        """
        data_json = json.dumps(heatmap_data, ensure_ascii=False)

        html_code = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Calendar Heatmap & Compliance Anomaly Visualizer</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=Tajawal:wght@400;500;700&display=swap" rel="stylesheet">
  
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Cairo', 'Tajawal', -apple-system, sans-serif;
      background-color: #0b1120;
      color: #f1f5f9;
      padding: 16px;
      direction: rtl;
    }}
    .hm-header {{
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #1e293b;
      flex-wrap: wrap; gap: 10px;
    }}
    .hm-title {{
      font-size: 18px; font-weight: 800; color: #38bdf8; display: flex; align-items: center; gap: 8px;
    }}
    .hm-badge {{
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: white; padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700;
    }}

    .kpi-row {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin-bottom: 18px;
    }}
    .kpi-card {{
      background: #131d31; border: 1px solid #1e293b; border-radius: 10px; padding: 10px 14px;
      display: flex; flex-direction: column; gap: 4px; border-right: 4px solid #38bdf8;
    }}
    .kpi-card.red {{ border-right-color: #ef4444; }}
    .kpi-card.amber {{ border-right-color: #f59e0b; }}
    .kpi-card.green {{ border-right-color: #10b981; }}
    .kpi-label {{ font-size: 11px; color: #94a3b8; font-weight: 600; }}
    .kpi-val {{ font-size: 18px; font-weight: 800; color: #f8fafc; }}

    /* Legend Bar */
    .legend-bar {{
      display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap;
      background: #131d31; border: 1px solid #1e293b; border-radius: 10px; padding: 10px 14px; margin-bottom: 16px;
    }}
    .legend-items {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; font-size: 11px; color: #cbd5e1; }}
    .legend-box {{
      width: 14px; height: 14px; border-radius: 3px; display: inline-block; vertical-align: middle; margin-left: 4px;
    }}

    /* Calendar Grid Matrix */
    .calendar-grid-box {{
      background: #131d31; border: 1px solid #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 16px;
    }}
    .month-header {{
      font-size: 14px; font-weight: 800; color: #38bdf8; margin: 12px 0 8px 0; display: flex; justify-content: space-between;
    }}
    .days-grid {{
      display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; margin-bottom: 16px;
    }}
    .weekday-header {{
      font-size: 11px; font-weight: 700; color: #64748b; text-align: center; padding-bottom: 4px;
    }}
    .day-cell {{
      aspect-ratio: 1; border-radius: 8px; background: #1e293b; border: 1px solid #334155;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      cursor: pointer; transition: all 0.2s ease; position: relative; padding: 2px;
    }}
    .day-cell:hover {{
      transform: scale(1.1); z-index: 10; border-color: #38bdf8; box-shadow: 0 4px 15px rgba(56, 189, 248, 0.4);
    }}
    .day-num {{ font-size: 11px; font-weight: 700; color: #f8fafc; }}
    .day-cnt {{ font-size: 9px; font-weight: 600; opacity: 0.9; margin-top: 1px; }}
    .anomaly-dot {{
      position: absolute; top: 3px; left: 3px; width: 6px; height: 6px; border-radius: 50%; background: #ef4444;
      box-shadow: 0 0 6px #ef4444; animation: pulseDot 1.5s infinite;
    }}
    @keyframes pulseDot {{
      0% {{ opacity: 1; transform: scale(1); }}
      50% {{ opacity: 0.4; transform: scale(1.3); }}
      100% {{ opacity: 1; transform: scale(1); }}
    }}

    /* Detail Modal Card */
    .detail-card {{
      background: #0f172a; border: 1px solid #38bdf8; border-radius: 12px; padding: 16px;
      margin-top: 16px; display: none; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
    }}
    .detail-head {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-bottom: 10px; }}
    .detail-date {{ font-size: 15px; font-weight: 800; color: #38bdf8; }}
    .reason-item {{ font-size: 12px; color: #fca5a5; background: rgba(239, 68, 68, 0.15); border-right: 3px solid #ef4444; padding: 6px 10px; border-radius: 4px; margin-top: 4px; }}
  </style>
</head>
<body>
  <div class="hm-header">
    <div class="hm-title">
      🗓️ خريطة الحرارة التقويمية لكثافة العمليات والشذوذ الرقابي (Calendar Anomaly Heatmap)
    </div>
    <div class="hm-badge">Visual Intelligence Engine</div>
  </div>

  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-label">إجمالي السجلات المراقبة</div>
      <div class="kpi-val" id="kpi-total-tx">0</div>
    </div>
    <div class="kpi-card green">
      <div class="kpi-label">إجمالي التدفقات المالية (SAR)</div>
      <div class="kpi-val" id="kpi-total-vol">0.00</div>
    </div>
    <div class="kpi-card red">
      <div class="kpi-label">أيام الشذوذ والتنبيهات 🚨</div>
      <div class="kpi-val" id="kpi-anom-days">0</div>
    </div>
    <div class="kpi-card amber">
      <div class="kpi-label">اليوم الأعلى كثافة للعمليات</div>
      <div class="kpi-val" id="kpi-peak-day" style="font-size: 14px;">—</div>
    </div>
  </div>

  <div class="legend-bar">
    <div style="font-size: 12px; font-weight: 700; color: #94a3b8;">🎨 دليل ألوان الخريطة الحرارية:</div>
    <div class="legend-items">
      <span><i class="legend-box" style="background:#1e293b;"></i> 0 حركات</span>
      <span><i class="legend-box" style="background:#0284c7;"></i> نشاط منخفض (1–5)</span>
      <span><i class="legend-box" style="background:#0369a1;"></i> نشاط متوسط (6–14)</span>
      <span><i class="legend-box" style="background:#f59e0b;"></i> نشاط كثيف (15+)</span>
      <span><i class="legend-box" style="background:#ef4444;"></i> تنبيه أمني / شذوذ في الامتثال 🚨</span>
    </div>
  </div>

  <div class="calendar-grid-box" id="calendarGrid">
    <!-- Rendered dynamically by JavaScript -->
  </div>

  <div class="detail-card" id="detailCard">
    <div class="detail-head">
      <div class="detail-date" id="detDate">التاريخ المختارات</div>
      <div style="font-size: 11px; color: #94a3b8;" id="detStatus">تفاصيل اليوم</div>
    </div>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; font-size: 12px; margin-bottom: 10px;">
      <div>📊 عدد العمليات: <b id="detTx" style="color:#38bdf8;">0</b></div>
      <div>💰 الحجم المالي: <b id="detVol" style="color:#10b981;">0 ريال</b></div>
      <div>🔄 التعديلات والعكس: <b id="detMods" style="color:#f59e0b;">0</b></div>
      <div>🚨 مؤشر الشذوذ: <b id="detAnom" style="color:#ef4444;">سليم</b></div>
    </div>
    <div id="detReasons"></div>
  </div>

  <script>
    const payload = {data_json};
    const cDays = payload.calendar_days || {{}};
    const metrics = payload.metrics || {{}};

    // Update Top KPIs
    document.getElementById('kpi-total-tx').innerText = metrics.total_transactions.toLocaleString('ar-SA');
    document.getElementById('kpi-total-vol').innerText = metrics.total_volume_sar.toLocaleString('ar-SA', {{ minimumFractionDigits: 2 }}) + ' ريال';
    document.getElementById('kpi-anom-days').innerText = metrics.anomaly_days_count + ' يوم';
    document.getElementById('kpi-peak-day').innerText = metrics.peak_tx_day + ' (' + metrics.peak_tx_count + ' عملية)';

    function renderCalendarGrid() {{
      const gridBox = document.getElementById('calendarGrid');
      gridBox.innerHTML = '';

      const weekdaysAr = ['السبت', 'الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة'];

      // Group days by month (YYYY-MM)
      const monthsMap = {{}};
      Object.keys(cDays).sort().forEach(dKey => {{
        const monthKey = dKey.substring(0, 7);
        if (!monthsMap[monthKey]) monthsMap[monthKey] = [];
        monthsMap[monthKey].push(cDays[dKey]);
      }});

      if (Object.keys(monthsMap).length === 0) {{
        gridBox.innerHTML = '<div style="text-align:center; color:#64748b; padding:20px;">لا توجد بيانات مسجلة في هذا النطاق الزمني.</div>';
        return;
      }}

      const ARABIC_MONTH_NAMES = {{
        '01': 'يناير', '02': 'فبراير', '03': 'مارس', '04': 'أبريل', '05': 'مايو', '06': 'يونيو',
        '07': 'يوليو', '08': 'أغسطس', '09': 'سبتمبر', '10': 'أكتوبر', '11': 'نوفمبر', '12': 'ديسمبر'
      }};

      Object.keys(monthsMap).forEach(mKey => {{
        const parts = mKey.split('-');
        const monthTitle = (ARABIC_MONTH_NAMES[parts[1]] || parts[1]) + ' ' + parts[0];

        const mHeader = document.createElement('div');
        mHeader.className = 'month-header';
        mHeader.innerHTML = `<span>🗓️ ${{monthTitle}}</span> <span style="font-size:11px; color:#64748b;">${{monthsMap[mKey].length}} يوماً مسجلاً</span>`;
        gridBox.appendChild(mHeader);

        // Weekday header row
        const wkRow = document.createElement('div');
        wkRow.className = 'days-grid';
        weekdaysAr.forEach(wk => {{
          const wkEl = document.createElement('div');
          wkEl.className = 'weekday-header';
          wkEl.innerText = wk;
          wkRow.appendChild(wkEl);
        }});
        gridBox.appendChild(wkRow);

        // Days grid
        const dGrid = document.createElement('div');
        dGrid.className = 'days-grid';

        monthsMap[mKey].forEach(dObj => {{
          const cell = document.createElement('div');
          cell.className = 'day-cell';
          cell.style.background = dObj.color;

          const dayNum = dObj.date.split('-')[2];

          cell.innerHTML = `
            <div class="day-num">${{dayNum}}</div>
            <div class="day-cnt">${{dObj.tx_count > 0 ? dObj.tx_count + ' ح' : '—'}}</div>
          `;

          if (dObj.is_anomaly) {{
            const dot = document.createElement('div');
            dot.className = 'anomaly-dot';
            cell.appendChild(dot);
          }}

          cell.onclick = () => showDayDetail(dObj);
          dGrid.appendChild(cell);
        }});

        gridBox.appendChild(dGrid);
      }});
    }}

    function showDayDetail(dObj) {{
      const modal = document.getElementById('detailCard');
      modal.style.display = 'block';

      document.getElementById('detDate').innerText = '📅 تفاصيل يوم ' + dObj.date;
      document.getElementById('detTx').innerText = dObj.tx_count + ' عملية';
      document.getElementById('detVol').innerText = dObj.financial_volume_sar.toLocaleString('ar-SA') + ' ريال';
      document.getElementById('detMods').innerText = dObj.modifications_count + ' تعديل/عكس';
      document.getElementById('detAnom').innerText = dObj.is_anomaly ? 'تنبيه أمني وشذوذ 🚨' : 'طبيعي ومطابق ✅';
      document.getElementById('detAnom').style.color = dObj.is_anomaly ? '#ef4444' : '#10b981';

      const reasonsBox = document.getElementById('detReasons');
      reasonsBox.innerHTML = '';

      if (dObj.anomaly_reasons && dObj.anomaly_reasons.length) {{
        reasonsBox.innerHTML = '<div style="font-size:11px; font-weight:700; color:#fca5a5; margin-top:6px;">🚨 التنبيهات المرصودة:</div>';
        dObj.anomaly_reasons.forEach(r => {{
          const rEl = document.createElement('div');
          rEl.className = 'reason-item';
          rEl.innerText = r;
          reasonsBox.appendChild(rEl);
        }});
      }}
    }}

    renderCalendarGrid();
  </script>
</body>
</html>
"""
        return html_code


def render_calendar_heatmap_ui(db_session: Any, key_prefix: str = "cal_hm", height: int = 740) -> None:
    """
    مكون Streamlit لعرض الخريطة الحرارية التقويمية ورصد الشذوذ في لوحة التحكم
    """
    import streamlit as st
    import streamlit.components.v1 as components

    c1, c2 = st.columns([3, 1])
    with c1:
        st.caption("خريطة حرارية تقويمية توضح كثافة حركات السجل اليومية ورصد التنبيهات الأمنية والشذوذ في أحجام التعاملات.")
    with c2:
        selected_year = st.selectbox("اختر السنة المالية:", [2026, 2025, 2024], index=0, key=f"{key_prefix}_year")

    heatmap_payload = HeatmapService.aggregate_calendar_heatmap_data(db_session, year=selected_year)
    html_content = HeatmapService.generate_heatmap_html(heatmap_payload)

    components.html(html_content, height=height, scrolling=True)
