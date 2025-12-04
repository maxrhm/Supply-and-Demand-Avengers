import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
import matplotlib.pyplot as plt

# This script loads M5-style datasets and produces sales-related nested donut charts.
# Expected files in the working directory (or provide via --data-dir):
# - calendar.csv
# - sales_train_evaluation.csv
# - sales_train_validation.csv
# - sample_submission.csv (not directly used for charts, validated for presence)
# - sell_prices.csv
#
# Charts generated:
# 1) Nested donut: outer ring by department_id, inner ring by category_id (sum of sales quantities)
# 2) Nested donut: outer ring by state_id, inner ring by store_id
#
# Aggregations use the sales_train_validation.csv by default; you can switch to evaluation via --use-eval.


def load_data(data_dir: Path, use_eval: bool = False) -> Dict[str, pd.DataFrame]:
    files = {
        "calendar.csv": data_dir / "calendar.csv",
        "sales_train_validation.csv": data_dir / "sales_train_validation.csv",
        "sales_train_evaluation.csv": data_dir / "sales_train_evaluation.csv",
        "sample_submission.csv": data_dir / "sample_submission.csv",
        "sell_prices.csv": data_dir / "sell_prices.csv",
    }

    missing = [fname for fname, fpath in files.items() if not fpath.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing required files in data directory.\n"
            f"Data directory: {data_dir.resolve()}\n"
            f"Missing: {', '.join(missing)}\n"
            "Tip: run with --data-dir pointing to the folder containing the CSVs,\n"
            "e.g., from scripts/ use --data-dir .."
        )

    calendar = pd.read_csv(files["calendar.csv"])
    sell_prices = pd.read_csv(files["sell_prices.csv"])  # Not directly used for quantity charts; kept for extensibility
    sales = pd.read_csv(files["sales_train_evaluation.csv" if use_eval else "sales_train_validation.csv"])  # Wide-format daily columns d_1...d_N
    submission = pd.read_csv(files["sample_submission.csv"])  # presence validation

    return {
        "calendar": calendar,
        "sell_prices": sell_prices,
        "sales": sales,
        "submission": submission,
    }


def melt_sales_to_long(sales: pd.DataFrame) -> pd.DataFrame:
    # Identify day columns (M5 format: d_1, d_2, ...)
    day_cols = [c for c in sales.columns if c.startswith("d_")]
    id_cols = [c for c in sales.columns if c not in day_cols]
    long_df = sales.melt(id_vars=id_cols, value_vars=day_cols, var_name="d", value_name="qty")
    long_df["qty"] = long_df["qty"].fillna(0)
    return long_df


def aggregate_by_dept_category(long_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    # Outer: dept_id totals; Inner: cat_id totals (M5 column names)
    dept_col = "dept_id" if "dept_id" in long_df.columns else "department_id"
    cat_col = "cat_id" if "cat_id" in long_df.columns else "category_id"
    if dept_col not in long_df.columns:
        raise KeyError("Expected 'dept_id' or 'department_id' in sales data")
    if cat_col not in long_df.columns:
        raise KeyError("Expected 'cat_id' or 'category_id' in sales data")

    dept_totals = (
        long_df.groupby([dept_col], as_index=False)["qty"].sum().sort_values("qty", ascending=False)
    )
    cat_totals = (
        long_df.groupby([cat_col], as_index=False)["qty"].sum().sort_values("qty", ascending=False)
    )
    return dept_totals, cat_totals


def aggregate_by_state_store(long_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    # Outer: state_id totals; Inner: store_id totals
    state_totals = (
        long_df.groupby(["state_id"], as_index=False)["qty"].sum().sort_values("qty", ascending=False)
    )
    store_totals = (
        long_df.groupby(["store_id"], as_index=False)["qty"].sum().sort_values("qty", ascending=False)
    )
    return state_totals, store_totals


def _nested_donut(
    ax,
    outer_labels: List[str], outer_sizes: List[float], outer_colors: List[str],
    inner_labels: List[str], inner_sizes: List[float], inner_colors: List[str],
    title: str,
    outer_norm=None,
    outer_cmap=None,
    inner_norm=None,
    inner_cmap=None,
) -> None:
    # Outer ring with percentage labels (returns patches, texts, autotexts)
    wedges_outer, texts_outer, autotexts_outer = ax.pie(
        outer_sizes,
        labels=outer_labels,
        labeldistance=0.85,
        colors=outer_colors,
        startangle=90,
        radius=1.0,
        wedgeprops=dict(width=0.3, edgecolor="white"),
        autopct=lambda pct: f"{pct:.1f}%",
        pctdistance=0.95,
    )
    # Inner ring with percentage labels
    ax.pie(
        inner_sizes,
        labels=inner_labels,
        labeldistance=0.75,
        colors=inner_colors,
        startangle=90,
        radius=0.7,
        wedgeprops=dict(width=0.3, edgecolor="white"),
        autopct=lambda pct: f"{pct:.1f}%",
        pctdistance=0.8,
    )
    # Center circle for donut appearance
    centre_circle = plt.Circle((0, 0), 0.4, color="white", fc="white", linewidth=0)
    ax.add_artist(centre_circle)
    ax.set(aspect="equal", title=title)
    # Legend on the right with percentages (e.g., CA - 12.3%)
    total_outer = sum(outer_sizes) if len(outer_sizes) else 1
    legend_labels_outer = [f"{lbl} _ {size / total_outer * 100:.1f}%" for lbl, size in zip(outer_labels, outer_sizes)]
    ax.legend(wedges_outer, legend_labels_outer, title="Outer", loc="center left", bbox_to_anchor=(1.0, 0.5), ncol=1)
    
        # Inner legend removed to resolve indentation issues; outer legend remains on the right.

    # Optional scale bars (colorbars) for outer/inner quantities when colormaps provided
    # Color scale bars removed per request


def make_colors(n: int, base: str) -> List[str]:
    # Simple shade variations around a base color by interpolating alpha (not perfect, but readable)
    # Use a colormap for better palettes if desired.
    from matplotlib.colors import to_rgb
    r, g, b = to_rgb(base)
    shades = []
    for i in range(n):
        t = 0.3 + 0.7 * (i / max(1, n - 1))
        shades.append((r * t + (1 - t), g * t + (1 - t), b * t + (1 - t)))
    return [plt.cm.colors.to_hex(c) for c in shades]


def generate_charts(data: Dict[str, pd.DataFrame], out_dir: Path) -> List[Path]:
    sales = data["sales"]
    long_df = melt_sales_to_long(sales)

    # Chart 1: dept/category (nested donut)
    dept_totals, cat_totals = aggregate_by_dept_category(long_df)
    # Use whatever column exists (dept_id or department_id)
    dept_label_col = "dept_id" if "dept_id" in dept_totals.columns else "department_id"
    outer_labels_1 = dept_totals[dept_label_col].astype(str).tolist()
    outer_sizes_1 = dept_totals["qty"].tolist()
    cat_label_col = "cat_id" if "cat_id" in cat_totals.columns else "category_id"
    inner_labels_1 = cat_totals[cat_label_col].astype(str).tolist()
    inner_sizes_1 = cat_totals["qty"].tolist()

    # Map sizes to colors via colormaps and add scale bars
    import seaborn as sns
    from matplotlib import colors
    # Use seaborn palettes as colormaps - different for outer vs inner
    flare_cmap = sns.color_palette("flare", as_cmap=True)
    magma_cmap = sns.color_palette("magma", as_cmap=True)
    outer_norm_1 = colors.Normalize(vmin=min(outer_sizes_1), vmax=max(outer_sizes_1))
    inner_norm_1 = colors.Normalize(vmin=min(inner_sizes_1), vmax=max(inner_sizes_1))
    outer_cmap_1 = flare_cmap
    inner_cmap_1 = magma_cmap
    outer_colors_1 = [outer_cmap_1(outer_norm_1(s)) for s in outer_sizes_1]
    inner_colors_1 = [inner_cmap_1(inner_norm_1(s)) for s in inner_sizes_1]

    fig1, ax1 = plt.subplots(figsize=(10, 10))
    _nested_donut(
        ax1,
        outer_labels_1,
        outer_sizes_1,
        outer_colors_1,
        inner_labels_1,
        inner_sizes_1,
        inner_colors_1,
        title="Sales Quantity by Department (outer) and Category (inner)",
        outer_norm=outer_norm_1,
        outer_cmap=outer_cmap_1,
        inner_norm=inner_norm_1,
        inner_cmap=inner_cmap_1,
    )
    out1 = out_dir / "sales_pie_dept_category.png"
    fig1.tight_layout()
    fig1.savefig(out1, dpi=150)
    plt.close(fig1)

    # Chart 2: state/store (nested donut)
    state_totals, store_totals = aggregate_by_state_store(long_df)
    outer_labels_2 = state_totals["state_id"].astype(str).tolist()
    outer_sizes_2 = state_totals["qty"].tolist()
    inner_labels_2 = store_totals["store_id"].astype(str).tolist()
    inner_sizes_2 = store_totals["qty"].tolist()

    import seaborn as sns
    from matplotlib import colors
    viridis_cmap = sns.color_palette("viridis", as_cmap=True)
    magma_cmap2 = sns.color_palette("magma", as_cmap=True)
    outer_norm_2 = colors.Normalize(vmin=min(outer_sizes_2), vmax=max(outer_sizes_2))
    inner_norm_2 = colors.Normalize(vmin=min(inner_sizes_2), vmax=max(inner_sizes_2))
    outer_cmap_2 = viridis_cmap
    inner_cmap_2 = magma_cmap2
    outer_colors_2 = [outer_cmap_2(outer_norm_2(s)) for s in outer_sizes_2]
    inner_colors_2 = [inner_cmap_2(inner_norm_2(s)) for s in inner_sizes_2]

    fig2, ax2 = plt.subplots(figsize=(10, 10))
    _nested_donut(
        ax2,
        outer_labels_2,
        outer_sizes_2,
        outer_colors_2,
        inner_labels_2,
        inner_sizes_2,
        inner_colors_2,
        title="Sales Quantity by State (outer) and Store (inner)",
        outer_norm=outer_norm_2,
        outer_cmap=outer_cmap_2,
        inner_norm=inner_norm_2,
        inner_cmap=inner_cmap_2,
    )
    out2 = out_dir / "sales_pie_state_store.png"
    fig2.tight_layout()
    fig2.savefig(out2, dpi=150)
    plt.close(fig2)

    # Chart 3: single-layer pie by department (default palette)
    fig3, ax3 = plt.subplots(figsize=(8, 8))
    wedges3, texts3, autotexts3 = ax3.pie(
        outer_sizes_1,
        labels=outer_labels_1,
        startangle=90,
        autopct=lambda pct: f"{pct:.1f}%",
    )
    # Legend on the right
    total_dept = sum(outer_sizes_1) if len(outer_sizes_1) else 1
    legend_labels_dept = [
        f"{lbl} _ {size / total_dept * 100:.1f}%" for lbl, size in zip(outer_labels_1, outer_sizes_1)
    ]
    ax3.legend(
        wedges3,
        legend_labels_dept,
        title="Department",
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
        ncol=1,
    )
    ax3.set(aspect="equal", title="Sales Quantity by Department (single-layer)")
    out3 = out_dir / "sales_pie_department_single.png"
    fig3.tight_layout()
    fig3.savefig(out3, dpi=150)
    plt.close(fig3)

    # Chart 4: single-layer pie by state (default palette)
    fig4, ax4 = plt.subplots(figsize=(8, 8))
    wedges4, texts4, autotexts4 = ax4.pie(
        outer_sizes_2,
        labels=outer_labels_2,
        startangle=90,
        autopct=lambda pct: f"{pct:.1f}%",
    )
    # Legend on the right
    total_state = sum(outer_sizes_2) if len(outer_sizes_2) else 1
    legend_labels_state = [
        f"{lbl} _ {size / total_state * 100:.1f}%" for lbl, size in zip(outer_labels_2, outer_sizes_2)
    ]
    ax4.legend(
        wedges4,
        legend_labels_state,
        title="State",
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
        ncol=1,
    )
    ax4.set(aspect="equal", title="Sales Quantity by State (single-layer)")
    out4 = out_dir / "sales_pie_state_single.png"
    fig4.tight_layout()
    fig4.savefig(out4, dpi=150)
    plt.close(fig4)

    return [out1, out2, out3, out4]


def main(argv: List[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Generate sales-related nested pie charts from M5 datasets.")
    parser.add_argument("--data-dir", type=str, default=".", help="Directory containing required CSV files")
    parser.add_argument("--use-eval", action="store_true", help="Use sales_train_evaluation.csv instead of validation")
    parser.add_argument("--out-dir", type=str, default="reports", help="Directory to save charts")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = load_data(data_dir, use_eval=args.use_eval)
    outputs = generate_charts(data, out_dir)

    print("Generated charts:")
    for p in outputs:
        print(f" - {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
