import sys
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

"""
Sales Bar Report

Generates bar charts to monitor sales performance using M5-style datasets.
Inputs expected in --data-dir:
- sales_train_validation.csv
- sales_train_evaluation.csv
- sample_submission.csv (validated for presence)
- sell_prices.csv

Charts:
1) Total quantity by state (bar)
2) Total quantity by department (bar)
3) Average price by (store_id, item_id) top-N (bar)
4) Quantity trend by week (bar) — validation vs evaluation comparison

Usage:
  python scripts/sales_bar_report.py --data-dir . --out-dir reports --top-n 20 --use-eval
"""


def load_data(data_dir: Path, use_eval: bool) -> Dict[str, pd.DataFrame]:
    files = {
        "sales_val": data_dir / "sales_train_validation.csv",
        "sales_eval": data_dir / "sales_train_evaluation.csv",
        "submission": data_dir / "sample_submission.csv",
        "sell_prices": data_dir / "sell_prices.csv",
        "calendar": data_dir / "calendar.csv",
    }
    required = ["sales_val", "sales_eval"]
    missing_required = [k for k in required if not files[k].exists()]
    if missing_required:
        raise FileNotFoundError(
            "Missing required sales files in data directory.\n"
            f"Data directory: {data_dir.resolve()}\n"
            f"Missing: {', '.join(missing_required)}\n"
            "Tip: run from scripts/ with --data-dir .. if CSVs are in project root."
        )

    # Load mandatory
    sales = pd.read_csv(files["sales_eval" if use_eval else "sales_val"])  # wide daily format d_1...d_N

    # Load optional datasets if present
    sell_prices = pd.read_csv(files["sell_prices"]) if files["sell_prices"].exists() else None
    submission = pd.read_csv(files["submission"]) if files["submission"].exists() else None
    calendar = pd.read_csv(files["calendar"]) if files["calendar"].exists() else None

    return {"sales": sales, "sell_prices": sell_prices, "submission": submission, "calendar": calendar}


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
    # Sum across all items per day to avoid melt memory blow-up
    day_sum = df[day_cols].sum(axis=0).reset_index()
    day_sum.columns = ["d", "qty"]
    if calendar is not None and set(["d", "year", "wm_yr_wk"]).issubset(calendar.columns):
        merged = day_sum.merge(calendar[["d", "year", "wm_yr_wk"]], on="d", how="left")
        merged["year"] = merged["year"].astype("Int64")
        merged["wm_yr_wk"] = merged["wm_yr_wk"].astype("Int64")
        out = merged.groupby(["year", "wm_yr_wk"], as_index=False)["qty"].sum()
    else:
        # Fallback: derive pseudo-week number
        merged = day_sum.copy()
        merged["d_num"] = merged["d"].str.replace("d_", "").astype(int)
        merged["wm_yr_wk"] = ((merged["d_num"] - 1) // 7) + 1
        merged["year"] = pd.NA
        out = merged.groupby(["year", "wm_yr_wk"], as_index=False)["qty"].sum()
    return out


def chart_total_by_state(df: pd.DataFrame, out_dir: Path) -> Path:
    agg = totals_by_state(df).sort_values("qty", ascending=False)
    plt.figure(figsize=(10, 6))
    # Use a single color to avoid seaborn palette+hue FutureWarning
    state_color = sns.color_palette("viridis")[3]
    sns.barplot(data=agg, x="state_id", y="qty", color=state_color, legend=False)
    plt.title("Total Quantity by State")
    plt.xlabel("State")
    plt.ylabel("Quantity")
    plt.tight_layout()
    out = out_dir / "bar_total_by_state.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def chart_total_by_dept(df: pd.DataFrame, out_dir: Path) -> Path:
    agg = totals_by_dept(df).sort_values("qty", ascending=False)
    plt.figure(figsize=(10, 6))
    dept_color = sns.color_palette("flare")[2]
    sns.barplot(data=agg, x="dept", y="qty", color=dept_color, legend=False)
    plt.title("Total Quantity by Department")
    plt.xlabel("Department")
    plt.ylabel("Quantity")
    plt.tight_layout()
    out = out_dir / "bar_total_by_department.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def chart_avg_price_topN(sell_prices: pd.DataFrame, top_n: int, out_dir: Path) -> Path:
    # Average price per (store_id, item_id), show top-N by avg price
    agg = (
        sell_prices.groupby(["store_id", "item_id"], as_index=False)["sell_price"].mean()
        .sort_values("sell_price", ascending=False)
        .head(top_n)
    )
    plt.figure(figsize=(12, 7))
    sns.barplot(data=agg, x="sell_price", y="item_id", hue="store_id", dodge=False, palette="magma")
    plt.title(f"Top {top_n} Avg Sell Price by Item and Store")
    plt.xlabel("Average Sell Price")
    plt.ylabel("Item ID")
    plt.legend(title="Store", bbox_to_anchor=(1.0, 0.5), loc="center left")
    plt.tight_layout()
    out = out_dir / "bar_avg_price_topN.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def chart_weekly_qty(val_df: pd.DataFrame, eval_df: Optional[pd.DataFrame], calendar: Optional[pd.DataFrame], out_dir: Path) -> Path:
    # Convert to scatter plot; categorize x-axis into year (uses calendar if available)
    def with_calendar(df: pd.DataFrame) -> pd.DataFrame:
        if calendar is not None and "d" in calendar.columns and "year" in calendar.columns and "wm_yr_wk" in calendar.columns:
            merged = df.merge(calendar[["d", "year", "wm_yr_wk"]], on="d", how="left")
            merged["year"] = merged["year"].astype("Int64")
            merged["wm_yr_wk"] = merged["wm_yr_wk"].astype("Int64")
            return merged
        # Fallback: derive pseudo-week and unknown year
        tmp = df.copy()
        tmp["d_num"] = tmp["d"].str.replace("d_", "").astype(int)
        tmp["wm_yr_wk"] = ((tmp["d_num"] - 1) // 7) + 1
        tmp["year"] = pd.NA
        return tmp

    # Compute weekly totals without melting large dataframes
    val_w = weekly_totals_from_wide(val_df, calendar)

    plt.figure(figsize=(12, 6))
    sns.scatterplot(data=val_w, x="wm_yr_wk", y="qty", hue="year", palette="viridis", alpha=0.7)
    # No line overlays per request; scatter only

    if eval_df is not None:
        eval_w = weekly_totals_from_wide(eval_df, calendar)
        sns.scatterplot(data=eval_w, x="wm_yr_wk", y="qty", hue="year", palette="flare", marker="X", alpha=0.7)
        # No line overlays per request; scatter only
        # Build a combined legend to indicate dataset semantics
        from matplotlib.lines import Line2D
        custom_handles = [
            Line2D([0], [0], color=sns.color_palette("viridis")[0], marker='o', linestyle='-', alpha=0.6, label='Validation'),
            Line2D([0], [0], color=sns.color_palette("flare")[0], marker='X', linestyle='--', alpha=0.6, label='Evaluation'),
        ]
        dataset_legend = plt.legend(
            handles=custom_handles,
            title="Dataset",
            loc="lower left",
            bbox_to_anchor=(1.02, 0.0),
            borderaxespad=0.0
        )
        plt.gca().add_artist(dataset_legend)

        # Secondary legend: Year color mapping (combine years from both val and eval)
        years = pd.concat([val_w["year"], eval_w["year"]]).dropna().unique()
        year_handles = []
        viridis = sns.color_palette("viridis", n_colors=max(3, len(years)))
        for i, y in enumerate(sorted(years)):
            year_handles.append(Line2D([0], [0], color=viridis[i % len(viridis)], marker='o', linestyle='-', label=str(y)))
        if year_handles:
            plt.legend(
                handles=year_handles,
                title="Year",
                loc="upper left",
                bbox_to_anchor=(1.02, 1.0),
                borderaxespad=0.0
            )
    else:
        # Only validation present: show year legend based on val_w
        years = val_w["year"].dropna().unique()
        from matplotlib.lines import Line2D
        year_handles = []
        viridis = sns.color_palette("viridis", n_colors=max(3, len(years)))
        for i, y in enumerate(sorted(years)):
            year_handles.append(Line2D([0], [0], color=viridis[i % len(viridis)], marker='o', linestyle='-', label=str(y)))
        if year_handles:
            plt.legend(
                handles=year_handles,
                title="Year",
                loc="upper left",
                bbox_to_anchor=(1.02, 1.0),
                borderaxespad=0.0
            )

    plt.title("Weekly Quantity Scatter Plot by Year")
    plt.xlabel("Week (wm_yr_wk)")
    plt.ylabel("Quantity")
    plt.tight_layout()
    out = out_dir / "scatter_weekly_quantity_by_year.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    return out


def main(argv: List[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Generate sales performance bar charts from M5 datasets.")
    parser.add_argument("--data-dir", type=str, default=".", help="Directory containing required CSV files")
    parser.add_argument("--out-dir", type=str, default="reports", help="Directory to save charts")
    parser.add_argument("--top-n", type=int, default=20, help="Top-N for avg price chart")
    parser.add_argument("--use-eval", action="store_true", help="Use evaluation dataset for quantity charts")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data_eval = load_data(data_dir, use_eval=True)
    data_val = load_data(data_dir, use_eval=False)

    outputs: List[Path] = []
    outputs.append(chart_total_by_state(data_val["sales"], out_dir))
    outputs.append(chart_total_by_dept(data_val["sales"], out_dir))
    if isinstance(data_val["sell_prices"], pd.DataFrame):
        outputs.append(chart_avg_price_topN(data_val["sell_prices"], args.top_n, out_dir))
    else:
        print("Warning: sell_prices.csv not found — skipping avg price chart.")
    outputs.append(chart_weekly_qty(data_val["sales"], (data_eval["sales"] if args.use_eval else None), data_val.get("calendar"), out_dir))

    print("Generated bar charts:")
    for p in outputs:
        print(f" - {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
