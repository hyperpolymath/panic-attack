#!/usr/bin/env python3
"""
Generate a risk distribution histogram for the mass-panic paper.
"""
import matplotlib.pyplot as plt
import numpy as np

# Risk distribution data (from paper)
categories = ['Healthy', 'Low', 'Moderate', 'High', 'Critical']
counts = [200, 50, 30, 15, 8]  # Example counts (adjust as needed)
colors = ['#4CAF50', '#8BC34A', '#FFC107', '#FF9800', '#F44336']

# Create histogram
plt.figure(figsize=(10, 6))
bars = plt.bar(categories, counts, color=colors, edgecolor='black', linewidth=1.5)

# Add labels and title
plt.xlabel('Risk Category', fontsize=12, fontweight='bold')
plt.ylabel('Number of Repositories', fontsize=12, fontweight='bold')
plt.title('Risk Distribution Across 303 Repositories', fontsize=14, fontweight='bold')

# Add value labels on top of bars
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2, height + 0.5, f'{int(height)}', 
             ha='center', va='bottom', fontweight='bold')

# Save as high-resolution PNG and SVG
plt.savefig('/var/mnt/eclipse/repos/games-ecosystem/panic-attacker/docs/figures/risk-distribution.png', 
            dpi=300, bbox_inches='tight')
plt.savefig('/var/mnt/eclipse/repos/games-ecosystem/panic-attacker/docs/figures/risk-distribution.svg', 
            bbox_inches='tight')

print("Histogram generated successfully!")