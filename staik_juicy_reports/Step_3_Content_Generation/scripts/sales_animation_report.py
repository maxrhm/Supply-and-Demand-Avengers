import sys
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib import animation

"""
Sales Animation Report

Generates an animated chart to complement:
- Weekly quantity by year (scatter/line)
- Sales pie by department
- Sales pie by state

This script renders a bar chart race of weekly quantities by department
(top-N departments per week), showing how departments change over time.

Inputs expected in --data-dir:
- sales_train_validation.csv
- sales_train_evaluation.csv (optional)
- calendar.csv (recommended for year/week mapping)

Usage:
  python scripts/sales_animation_report.py --data-dir . --out-dir reports --top-n 10 --use-eval
"""


def load_data(data_dir: Path, use_eval: bool) -> Dict[str, Optional[pd.DataFrame]]:
    files = {
        "sales_val": data_dir / "sales_train_validation.csv",
        "sales_eval": data_dir / "sales_train_evaluation.csv",
        "calendar": data_dir / "calendar.csv",
    }
    required = ["sales_val"]
    missing_required = [k for k in required if not files[k].exists()]
    if missing_required:
        raise FileNotFoundError(
            "Missing required sales files in data directory.\n"
            f"Data directory: {data_dir.resolve()}\n"
            f"Missing: {', '.join(missing_required)}\n"
            "Tip: run from scripts/ with --data-dir .. if CSVs are in project root."
        )

    sales = pd.read_csv(files["sales_eval" if (use_eval and files["sales_eval"].exists()) else "sales_val"])  # wide d_* format
    calendar = pd.read_csv(files["calendar"]) if files["calendar"].exists() else None
    return {"sales": sales, "calendar": calendar}


def get_day_cols(df: pd.DataFrame) -> List[str]:
    return [c for c in df.columns if c.startswith("d_")]


def weekly_dept_totals_from_wide(df: pd.DataFrame, calendar: Optional[pd.DataFrame]) -> pd.DataFrame:
    day_cols = get_day_cols(df)
    dept_col = "dept_id" if "dept_id" in df.columns else ("department_id" if "department_id" in df.columns else None)
    if not dept_col:
        raise KeyError("Expected 'dept_id' or 'department_id' in sales data")
    # Sum per department per day (avoid full melt of items)
    df_dept = df[[dept_col] + day_cols].copy()
    per_dept_day = df_dept.groupby(dept_col)[day_cols].sum()
    long = per_dept_day.reset_index().melt(id_vars=[dept_col], value_vars=day_cols, var_name="d", value_name="qty")
    if calendar is not None and set(["d", "year", "wm_yr_wk"]).issubset(calendar.columns):
        long = long.merge(calendar[["d", "year", "wm_yr_wk"]], on="d", how="left")
    else:
        long["d_num"] = long["d"].str.replace("d_", "").astype(int)
        long["wm_yr_wk"] = ((long["d_num"] - 1) // 7) + 1
        long["year"] = pd.NA
    out = long.groupby([dept_col, "year", "wm_yr_wk"], as_index=False)["qty"].sum()
    out.rename(columns={dept_col: "dept"}, inplace=True)
    return out


def weekly_state_totals_from_wide(df: pd.DataFrame, calendar: Optional[pd.DataFrame]) -> pd.DataFrame:
    day_cols = get_day_cols(df)
    state_col = "state_id" if "state_id" in df.columns else None
    if not state_col:
        raise KeyError("Expected 'state_id' in sales data")
    df_state = df[[state_col] + day_cols].copy()
    per_state_day = df_state.groupby(state_col)[day_cols].sum()
    long = per_state_day.reset_index().melt(id_vars=[state_col], value_vars=day_cols, var_name="d", value_name="qty")
    if calendar is not None and set(["d", "year", "wm_yr_wk"]).issubset(calendar.columns):
        long = long.merge(calendar[["d", "year", "wm_yr_wk"]], on="d", how="left")
    else:
        long["d_num"] = long["d"].str.replace("d_", "").astype(int)
        long["wm_yr_wk"] = ((long["d_num"] - 1) // 7) + 1
        long["year"] = pd.NA
    out = long.groupby([state_col, "year", "wm_yr_wk"], as_index=False)["qty"].sum()
    out.rename(columns={state_col: "state"}, inplace=True)
    return out


def animate_weekly_dept_totals(df: pd.DataFrame, calendar: Optional[pd.DataFrame], out_dir: Path, top_n: int = 10) -> Path:
    """Create an animated horizontal bar chart race for weekly department quantities."""
    data = weekly_dept_totals_from_wide(df, calendar)
    # Use week keys, sort for animation order
    weeks = sorted(data["wm_yr_wk"].dropna().unique())
    # Overall ordering by total to keep consistent y-axis
    dept_order = (
        data.groupby("dept")["qty"].sum().sort_values(ascending=False).index.tolist()
    )
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.set_style("whitegrid")
    palette = sns.color_palette("flare", n_colors=len(dept_order))
    color_map = {d: palette[i % len(palette)] for i, d in enumerate(dept_order)}

    def init():
        ax.clear()
        ax.set_title("Weekly Quantity by Department — Top N Bar Chart Race")
        ax.set_xlabel("Quantity")
        ax.set_ylabel("Department")
        return []

    def frame_data(week_val: int) -> pd.Series:
        # Aggregate per week per department to ensure unique index
        week_df = (
            data[data["wm_yr_wk"] == week_val]
            .groupby("dept", as_index=False)["qty"].sum()
            .set_index("dept")["qty"]
            .reindex(dept_order).fillna(0)
            .sort_values(ascending=False)
        )
        # Top-N slice
        return week_df.head(top_n)

    def update(frame_idx: int):
        week = weeks[frame_idx]
        ax.clear()
        wdf = frame_data(week)
        depts = list(wdf.index)
        vals = wdf.values
        colors = [color_map[d] for d in depts]
        ax.barh(depts[::-1], vals[::-1], color=colors[::-1])
        ax.set_title(f"Weekly Quantity by Department — Week {int(week)} (Top {top_n})")
        ax.set_xlabel("Quantity")
        ax.set_ylabel("Department")
        ax.set_xlim(0, max(1.0, data["qty"].max() * 1.1))
        # Annotate values
        for i, v in enumerate(vals[::-1]):
            ax.text(v + (data["qty"].max() * 0.01), i, f"{int(v)}", va="center")
        return []

    anim = animation.FuncAnimation(fig, update, init_func=init, frames=len(weeks), interval=500, blit=False)
    out_path = out_dir / f"anim_weekly_dept_top{top_n}.gif"
    try:
        writer = animation.PillowWriter(fps=2)
        anim.save(out_path, writer=writer)
    finally:
        plt.close(fig)
    return out_path


def animate_weekly_state_totals(df: pd.DataFrame, calendar: Optional[pd.DataFrame], out_dir: Path, top_n: int = 10) -> Path:
    """Animated horizontal bar chart race for weekly state quantities."""
    data = weekly_state_totals_from_wide(df, calendar)
    weeks = sorted(data["wm_yr_wk"].dropna().unique())
    state_order = (
        data.groupby("state")["qty"].sum().sort_values(ascending=False).index.tolist()
    )
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.set_style("whitegrid")
    palette = sns.color_palette("crest", n_colors=len(state_order))
    color_map = {s: palette[i % len(palette)] for i, s in enumerate(state_order)}

    def init():
        ax.clear()
        ax.set_title("Weekly Quantity by State — Top N Bar Chart Race")
        ax.set_xlabel("Quantity")
        ax.set_ylabel("State")
        return []

    def frame_data(week_val: int) -> pd.Series:
        week_df = (
            data[data["wm_yr_wk"] == week_val]
            .groupby("state", as_index=False)["qty"].sum()
            .set_index("state")["qty"]
            .reindex(state_order).fillna(0)
            .sort_values(ascending=False)
        )
        return week_df.head(top_n)

    def update(frame_idx: int):
        week = weeks[frame_idx]
        ax.clear()
        wdf = frame_data(week)
        states = list(wdf.index)
        vals = wdf.values
        colors = [color_map[s] for s in states]
        ax.barh(states[::-1], vals[::-1], color=colors[::-1])
        ax.set_title(f"Weekly Quantity by State — Week {int(week)} (Top {top_n})")
        ax.set_xlabel("Quantity")
        ax.set_ylabel("State")
        ax.set_xlim(0, max(1.0, data["qty"].max() * 1.1))
        for i, v in enumerate(vals[::-1]):
            ax.text(v + (data["qty"].max() * 0.01), i, f"{int(v)}", va="center")
        return []

    anim = animation.FuncAnimation(fig, update, init_func=init, frames=len(weeks), interval=500, blit=False)
    out_path = out_dir / f"anim_weekly_state_top{top_n}.gif"
    try:
        writer = animation.PillowWriter(fps=2)
        anim.save(out_path, writer=writer)
    finally:
        plt.close(fig)
    return out_path


def main(argv: List[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Generate animated weekly department quantity chart (bar chart race).")
    parser.add_argument("--data-dir", type=str, default=".", help="Directory containing required CSV files")
    parser.add_argument("--out-dir", type=str, default="reports", help="Directory to save charts")
    parser.add_argument("--top-n", type=int, default=10, help="Top-N departments per week to display")
    parser.add_argument("--use-eval", action="store_true", help="Use evaluation dataset if available")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = load_data(data_dir, use_eval=args.use_eval)
    out_anim_dept = animate_weekly_dept_totals(data["sales"], data.get("calendar"), out_dir, top_n=args.top_n)
    out_anim_state = animate_weekly_state_totals(data["sales"], data.get("calendar"), out_dir, top_n=args.top_n)

    print("Generated animations:")
    print(f" - {out_anim_dept}")
    print(f" - {out_anim_state}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
