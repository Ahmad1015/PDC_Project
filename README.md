# GPU-Accelerated Malware Signature Scanner 🔍⚡

A high-performance malware scanner that leverages GPU acceleration using CUDA and Python.  
This project was developed as part of the **Parallel and Distributed Computing (PDC)** course and secured **🏅 1st Position** in the final evaluation.

---

## 🏅 Highlights

- 🥇 **1st Position - PDC Final Project**
- 🚀 GPU-Accelerated scanning using **Numba CUDA**
- ⚙️ Signature-based malware detection
- 🧵 CPU-GPU batching for efficient parallelism
- 📂 Scans files and directories for known byte signatures
- ✅ Successfully tested using the **EICAR** test file

---

## 🧪 EICAR Test File

We tested our scanner using the standard **EICAR test file**, which is a harmless file developed to test antivirus software.  
It contains a known byte sequence that is **recognized by all major antivirus engines** as a test virus.

- [EICAR Official Info](https://www.eicar.org/download-anti-malware-testfile/)

✅ Our scanner was able to detect the EICAR test file correctly using byte signature matching.

---

## 🔑 ClamAV Signature Extraction

We used **real-world malware byte signatures** sourced from the [ClamAV](https://github.com/Cisco-Talos/clamav-devel) open-source antivirus engine.

- The file `signatures.txt` in this repository contains extracted byte patterns.
- Signature extraction scripts and tools are provided in the `tools/` folder.
- Link to the ClamAV signature source repository: [clamav-devel](https://github.com/Cisco-Talos/clamav-devel)

---

## 📸 Demo

<!-- Add a screenshot or GIF here if available -->
<!-- ![Demo](demo/demo.gif) -->

---


## 🚀 Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/gpu-malware-scanner.git
   cd gpu-malware-scanner
   ```

2. **Install dependencies**:

3. **Run the scanner**:
   ```bash
   python Backend/GPU/gpu_scanner.py
   ```

---

## 🛠️ Features

- Fast scanning of large files and directories using GPU parallelism
- Byte-pattern matching for known malware signatures
- Minimal dependencies – works with just Python, Numba, and NumPy
- Easily extendable to support additional signature formats
- Performance benchmarks included

---

## 🧠 Concepts Used

- GPU Programming with Numba CUDA
- Batch processing and memory management
- Signature-based malware detection
- Parallel execution with host-device synchronization
- Efficient file I/O and pattern matching

---

## 📜 Certificate

This project was awarded **1st Position** in the Parallel and distributed Computing ( PDC ) lab course evaluation.

![Ahmad_page-0001](https://github.com/user-attachments/assets/20969470-962c-44d8-b855-0180c7bc671f)


---

## 👨‍💻 Author

**Ahmad Raza**   
🎓 BSc Computer Science, PDC Final Project
