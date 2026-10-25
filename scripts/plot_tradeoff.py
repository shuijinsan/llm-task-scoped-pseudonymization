import json
import matplotlib.pyplot as plt
from pathlib import Path
import numpy as np

def plot_metrics():
    with open("results/smoke_test_metrics.json", "r") as f:
        data = json.load(f)

    modes = list(data.keys())
    f1_scores = [data[m]["f1"] for m in modes]
    
    balanced_accs = []
    for m in modes:
        tp = data[m].get("tp", 0); tn = data[m].get("tn", 0)
        fp = data[m].get("fp", 0); fn = data[m].get("fn", 0)
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        balanced_accs.append((tpr + tnr) / 2)

    x = np.arange(len(modes))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, f1_scores, width, label='F1 Score', color='#1f77b4')
    rects2 = ax.bar(x + width/2, balanced_accs, width, label='Balanced Accuracy', color='#ff7f0e')

    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('LLM Utility vs. Identifier Representation Strategies', fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([m.upper().replace("_", "-") for m in modes], fontsize=11)
    ax.set_ylim(0, 1.1)
    ax.legend(loc='lower left', fontsize=11)
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.2f}', xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=10)

    autolabel(rects1)
    autolabel(rects2)

    plt.tight_layout()
    plt.savefig("results/strategy_metrics.png", dpi=300, bbox_inches="tight")
    print("Plot saved to results/strategy_metrics.png")

if __name__ == "__main__":
    plot_metrics()
