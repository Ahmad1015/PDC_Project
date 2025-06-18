import matplotlib.pyplot as plt

# Data
sizes = [68, 1588, 3108, 16028, 47188, 93548, 175628]
serial_times = [4.91, 4.89, 4.87, 5.09, 5.3, 5.65, 6.4]
parallel_times = [5.397, 4.079, 3.845, 4.228, 4.96, 5.032, 5.12]

# Plot
plt.figure(figsize=(10, 6))
plt.plot(sizes, serial_times, color='red', marker='o', label='Serial')
plt.plot(sizes, parallel_times, color='blue', marker='s', label='Parallel')

# Aesthetics
plt.title("Serial vs Parallel Execution Time of Malware Scanner", fontsize=14)
plt.xlabel("Input Size (bytes)", fontsize=12)
plt.ylabel("Execution Time (seconds)", fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)
plt.legend()
plt.tight_layout()

# Show plot
plt.show()
