import sys
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import numpy as np

import plotly.express as px
import plotly.graph_objects as go

"""
Sales Plotly Report

Generates interactive charts (HTML) using Plotly based on M5-style datasets:
- sales_train_validation.csv (required)
- sales_train_evaluation.csv (optional via --use-eval)
- sample_submission.csv (optional)
- sell_prices.csv (optional)
- calendar.csv (optional)

Outputs are saved as self-contained HTML files under the chosen out directory.

Usage:
  python scripts/sales_plotly_report.py --data-dir . --out-dir reports --top-n 20 --use-eval
"""


def load_data(data_dir: Path, use_eval: bool) -> Dict[str, Optional[pd.DataFrame]]:
    files = {
        "sales_val": data_dir / "sales_train_validation.csv",
        "sales_eval": data_dir / "sales_train_evaluation.csv",
        "submission": data_dir / "sample_submission.csv",
        "sell_prices": data_dir / "sell_prices.csv",
        "calendar": data_dir / "calendar.csv",
    }
    # Only require validation sales; evaluation is optional
    if not files["sales_val"].exists():
        raise FileNotFoundError(
            "Missing required sales file 'sales_train_validation.csv'.\n"
            f"Data directory: {data_dir.resolve()}\n"
            "Tip: run from scripts/ with --data-dir .. if CSVs are in project root."
        )
    sales = pd.read_csv(files["sales_eval" if (use_eval and files["sales_eval"].exists()) else "sales_val"])  # wide d_* format
    # Also load validation and evaluation separately when available for interactive toggles
    sales_val = pd.read_csv(files["sales_val"]) if files["sales_val"].exists() else None
    sales_eval = pd.read_csv(files["sales_eval"]) if files["sales_eval"].exists() else None
    calendar = pd.read_csv(files["calendar"]) if files["calendar"].exists() else None
    sell_prices = pd.read_csv(files["sell_prices"]) if files["sell_prices"].exists() else None
    submission = pd.read_csv(files["submission"]) if files["submission"].exists() else None
    return {"sales": sales, "sales_val": sales_val, "sales_eval": sales_eval, "calendar": calendar, "sell_prices": sell_prices, "submission": submission}


def get_day_cols(df: pd.DataFrame) -> List[str]:
    return [c for c in df.columns if c.startswith("d_")]


def totals_by_state(df: pd.DataFrame) -> pd.DataFrame:
    day_cols = get_day_cols(df)
    tmp = df.copy()
    tmp["qty_total"] = tmp[day_cols].sum(axis=1)
    return tmp.groupby("state_id", as_index=False)["qty_total"].sum().rename(columns={"qty_total": "qty"})


def totals_by_dept(df: pd.DataFrame) -> pd.DataFrame:
    day_cols = get_day_cols(df)
    tmp = df.copy()
    tmp["qty_total"] = tmp[day_cols].sum(axis=1)
    dept_col = "dept_id" if "dept_id" in tmp.columns else ("department_id" if "department_id" in tmp.columns else None)
    if not dept_col:
        raise KeyError("Expected 'dept_id' or 'department_id' in sales data")
    return tmp.groupby(dept_col, as_index=False)["qty_total"].sum().rename(columns={"qty_total": "qty", dept_col: "dept"})


def weekly_totals_from_wide(df: pd.DataFrame, calendar: Optional[pd.DataFrame]) -> pd.DataFrame:
    day_cols = get_day_cols(df)
    day_sum = df[day_cols].sum(axis=0).reset_index()
    day_sum.columns = ["d", "qty"]
    if calendar is not None and set(["d", "year", "wm_yr_wk"]).issubset(calendar.columns):
        merged = day_sum.merge(calendar[["d", "year", "wm_yr_wk"]], on="d", how="left")
        merged["year"] = merged["year"].astype("Int64")
        merged["wm_yr_wk"] = merged["wm_yr_wk"].astype("Int64")
        out = merged.groupby(["year", "wm_yr_wk"], as_index=False)["qty"].sum()
    else:
        merged = day_sum.copy()
        merged["d_num"] = merged["d"].str.replace("d_", "").astype(int)
        merged["wm_yr_wk"] = ((merged["d_num"] - 1) // 7) + 1
        merged["year"] = pd.NA
        out = merged.groupby(["year", "wm_yr_wk"], as_index=False)["qty"].sum()
    return out


def chart_total_by_state_plotly(df: pd.DataFrame, out_dir: Path) -> Path:
    agg = totals_by_state(df).sort_values("qty", ascending=False)
    fig = px.bar(
        agg,
        x="state_id",
        y="qty",
        color="state_id",
        title="Total Quantity by State",
    )
    fig.update_layout(xaxis_title="State", yaxis_title="Quantity", legend_title_text="State")
    out = out_dir / "plotly_total_by_state.html"
    fig.write_html(out, include_plotlyjs="cdn")
    return out


def chart_total_by_dept_plotly(df: pd.DataFrame, out_dir: Path) -> Path:
    agg = totals_by_dept(df).sort_values("qty", ascending=False)
    # Use distinct colors per department for visual differentiation
    fig = px.bar(
        agg,
        x="dept",
        y="qty",
        color="dept",
        title="Total Quantity by Department",
    )
    fig.update_layout(xaxis_title="Department", yaxis_title="Quantity", legend_title_text="Department")
    out = out_dir / "plotly_total_by_department.html"
    fig.write_html(out, include_plotlyjs="cdn")
    return out


def chart_weekly_qty_plotly(data: Dict[str, Optional[pd.DataFrame]], out_dir: Path) -> Path:
    calendar = data.get("calendar")
    val_df = data.get("sales_val") if isinstance(data.get("sales_val"), pd.DataFrame) else data["sales"]
    eval_df = data.get("sales_eval")

    weekly_val = weekly_totals_from_wide(val_df, calendar)
    fig = px.line(weekly_val, x="wm_yr_wk", y="qty", color=("year" if "year" in weekly_val.columns else None),
                  title="Weekly Quantity by Year — Toggle Validation/Evaluation")
    fig.update_layout(xaxis_title="Week (wm_yr_wk)", yaxis_title="Quantity")

    # Add evaluation trace if available
    if isinstance(eval_df, pd.DataFrame):
        weekly_eval = weekly_totals_from_wide(eval_df, calendar)
        # Create a second trace
        fig.add_trace(go.Scatter(x=weekly_eval["wm_yr_wk"], y=weekly_eval["qty"], mode="lines",
                                 name="Evaluation", line=dict(color="orange")))
        # Build update menus to toggle visibility between Validation and Evaluation
        # Assume first trace(s) represent Validation; last added represents Evaluation
        n_traces = len(fig.data)
        # Show only Validation
        show_val = [True] * (n_traces - 1) + [False]
        # Show only Evaluation
        show_eval = [False] * (n_traces - 1) + [True]
        fig.update_layout(
            updatemenus=[
                dict(
                    type="buttons",
                    direction="left",
                    buttons=[
                        dict(label="Validation", method="update",
                             args=[{"visible": show_val}, {"title": "Weekly Quantity — Validation"}]),
                        dict(label="Evaluation", method="update",
                             args=[{"visible": show_eval}, {"title": "Weekly Quantity — Evaluation"}]),
                        dict(label="Both", method="update",
                             args=[{"visible": [True]*n_traces}, {"title": "Weekly Quantity — Both"}]),
                    ],
                    pad={"r": 10, "t": 10},
                    showactive=True,
                    x=0.0,
                    xanchor="left",
                    y=1.15,
                    yanchor="top",
                )
            ]
        )

    out = out_dir / "plotly_weekly_quantity_by_year.html"
    fig.write_html(out, include_plotlyjs="cdn")
    return out


def chart_price_trend_plotly(sell_prices: pd.DataFrame, out_dir: Path, top_n: int = 20) -> Path:
    # Select top-N item-store combos by average price, then plot price time series
    avg = (
        sell_prices.groupby(["store_id", "item_id"], as_index=False)["sell_price"].mean()
        .sort_values("sell_price", ascending=False)
        .head(top_n)
    )
    subset = sell_prices.merge(avg[["store_id", "item_id"]], on=["store_id", "item_id"], how="inner")
    fig = px.line(subset, x="wm_yr_wk", y="sell_price", color="item_id", line_group="store_id",
                  title=f"Sell Price Trend Top {top_n} Items by Avg Price")
    fig.update_layout(xaxis_title="Week (wm_yr_wk)", yaxis_title="Sell Price")
    out = out_dir / "plotly_price_trend_topN.html"
    fig.write_html(out, include_plotlyjs="cdn")
    return out


def chart_submission_preview_plotly(submission: pd.DataFrame, out_dir: Path, top_n: int = 50) -> Path:
    # Show a preview: sum of first top_n rows across day columns
    day_cols = [c for c in submission.columns if str(c).startswith("F") or str(c).startswith("d_")]
    if not day_cols:
        # If no day-like columns, just render table
        out = out_dir / "plotly_submission_preview.html"
        fig = go.Figure(data=[go.Table(header=dict(values=list(submission.columns)),
                                       cells=dict(values=[submission[c].head(top_n) for c in submission.columns]))])
        fig.update_layout(title="Sample Submission Preview (Top Rows)")
        fig.write_html(out, include_plotlyjs="cdn")
        return out
    sub = submission.head(top_n).copy()
    # Coerce to numeric and treat missing as 0 to avoid empty charts
    for c in day_cols:
        sub[c] = pd.to_numeric(sub[c], errors="coerce").fillna(0)
    totals = sub[day_cols].sum().reset_index()
    totals.columns = ["day", "sum"]
    ttl = f"Sample Submission Totals (Top {top_n} rows)"
    if float(totals["sum"].sum()) == 0.0:
        ttl += " — No numeric values found, treated missing as 0"
    fig = px.bar(totals, x="day", y="sum", title=ttl)
    fig.update_layout(xaxis_title="Day Column", yaxis_title="Sum")
    out = out_dir / "plotly_submission_totals.html"
    fig.write_html(out, include_plotlyjs="cdn")
    return out


def main(argv: List[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Generate interactive Plotly charts from M5 datasets.")
    parser.add_argument("--data-dir", type=str, default=".", help="Directory containing CSV files")
    parser.add_argument("--out-dir", type=str, default="reports", help="Directory to save HTML charts")
    parser.add_argument("--top-n", type=int, default=20, help="Top-N for price trend and submission totals")
    parser.add_argument("--use-eval", action="store_true", help="Use evaluation dataset if available")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = load_data(data_dir, use_eval=args.use_eval)

    outputs: List[Path] = []
    outputs.append(chart_total_by_state_plotly(data["sales"], out_dir))
    outputs.append(chart_total_by_dept_plotly(data["sales"], out_dir))
    outputs.append(chart_weekly_qty_plotly(data, out_dir))
    if isinstance(data.get("sell_prices"), pd.DataFrame):
        outputs.append(chart_price_trend_plotly(data["sell_prices"], out_dir, top_n=args.top_n))
    if isinstance(data.get("submission"), pd.DataFrame):
        outputs.append(chart_submission_preview_plotly(data["submission"], out_dir, top_n=args.top_n))

    print("Generated Plotly charts:")
    for p in outputs:
        print(f" - {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
