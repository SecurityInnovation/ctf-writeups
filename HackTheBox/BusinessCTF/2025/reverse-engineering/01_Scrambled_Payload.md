# Scrambled Payload - Business CTF 2025 Write-Up

## TL;DR

- **Challenge Name:** Scrambled Payload  
- **Category:** Reverse Engineering  
- **Difficulty:** Easy  
- **Tools Used:** Vim, Python, base64, Regex, Z3 Solver  
- **Techniques & Challenges:**  
  - Multi-layer VBScript deobfuscation  
  - Automated decoding using custom Python scripts  
  - Pattern recognition using regular expressions  
  - Symbolic constraint solving with Z3 for regex bypass

---

## Challenge Overview

We are provided with a ZIP file `rev_scrambledpayload.zip`, which contains a single file: `payload.vbs`. The `.vbs` extension indicates that this is a VBScript file. The file size is approximately 60KB and is heavily obfuscated.

---

## Step-by-Step Analysis

### 1. Initial Inspection

```bash
ls -lah
-rw-rw-r-- 1 asif asif  60K May 16 10:40 payload.vbs
```

```vb
Set A = CreateObject(Chr((211*95)mod 256)&Chr((187*169)mod 256)&C......
&Chr((172*103)mod 256):A.text = "<ONE_BIG_BASE64_ENCODED_PAYLOAD>":Set B=CreateObject("ADODB.Stream"):B.Type=1:B.Open:B.Write A.nodeTypedValue:B.Position=0:B.Type=2:B.CharSet=Chr((155*47)mod 256)&Chr((135*181)mod 256)&Chr((179*159)mod 256)&Chr((209*145)mod 256)&Chr((185*139)mod 256)&Chr((109*15)mod 256)&Chr((59*171)mod 256)&Chr(105):Execute B.ReadText
```

The VBScript begins by using `CreateObject` and assigning a base64 string to a variable, which is later written to a stream and executed. We extract the base64 payload using `Vim` and save it as `a_dot_text_b64_blob`.

### 2. Base64 Decoding

We decode the file:

```bash
cat a_dot_text_b64_blob | base64 -d > a_dot_text_b64_blob_decoded
```

Inside the decoded content, we find further obfuscation using arrays of integers, processed through operations  like `+ 196` or `* 117`, mod 256, then converted via `Chr()`.

```vb
d="":for i=0to 267:d=d+Chr((Array(143, 161, ..., 121, 110)(i)+196)mod 256):Next:Execute d
```

OR

```vb
d = ""
for i = 0 to 267
	d = d + Chr((Array(...)(i) + 196) mod 256)
Next
Execute d
```

### 3. Multi-Stage De-obfuscation with Python

We create a Python function that mimics the VBScript decoding logic:

```python
def deobfuscate_vbs_stage(obfuscated_array, loop_limit, op_type, op_val):
	d = ""
	for i in range(loop_limit + 1):
		res = 0
		val = obfuscated_array[i]

		if op_type == 'add':
            res = (val + op_val) % 256
        elif op_type == 'multiply':
            res = (val * op_val) % 256
        elif op_type == 'xor':
            res = (val ^ op_val) % 256

        d += chr(res)
    return d
```
This script is used to decode 9 stages, each producing part of the final VBScript.

### 4. Regex-Based De-obfuscation

The final decode script contains lines like:

```vb
Set b=CreateObject(Chr((201*185)mod 256)&Chr((228*153)mod 256)&Chr((217*103)mod 256)&.....
```

We use Python's `re` module to decode such patterns using three regex passes:
- Pass 1: Complex expressions like `Chr((X * Y) mod 256)`
- Pass 2: Simple expressions like `Chr(X)`
- Pass 3: Remove string concatenators (`&`)

```python
def deobfuscate_simple_chr(match) -> str:
    """
    Callback for Chr(NUM) pattern
    """
    try:
        num = int(match.group(1))
        return chr(num)
    except Exception as e:
        print(f"Error processing complex Chr pattern '{match.group(0)}' : {e}")
        return match.group(0)

def deobfuscate_complex_chr(match) -> str:
    """
    Callback for Chr((X OP Y) mod 256) pattern
    """
    try:
        x = int(match.group(1))
        op = str(match.group(2))
        y = int(match.group(3))

        # Vim inspection revealed only '*'
        assert(op == '*')
        res = (x * y) % 256
        return chr(res)
    except Exception as e:
        print(f"Error processing complex Chr pattern '{match.group(0)}' : {e}")
        return match.group(0)


def fully_deobfuscate(input_content: str) -> None:
    """
    Deobfuscate all Chr() patterns
    """

    # Pass 1: Complex Regex Patterns (built usign regex101.com)
    # e.g: Chr((197*55)mod 256)&
    complex_chr_pattern = r"Chr\(\((\d+)(\D)(\d+)\)\s*mod\s*\d*\)"
    deobfuscated_content = re.sub(complex_chr_pattern, deobfuscate_complex_chr, input_content)

    print(f"After Pass 1: Complex Chr DeObfuscation: \n{deobfuscated_content}")
    
    # Pass 2: Simple Regex Patterns (built usign regex101.com)
    # e.g: Chr(105)&
    simple_chr_pattern = r"Chr\((\d+)\)"
    deobfuscated_content = re.sub(simple_chr_pattern, deobfuscate_simple_chr, deobfuscated_content)
    print(f"After Pass 2: Simple Chr DeObfuscation: \n{deobfuscated_content}")

    # Pass 3: Cleanup by removing all '&'
    pattern_ampersand = r"(&)"
    deobfuscated_content = re.sub(pattern_ampersand, "", deobfuscated_content)
    print(f"After Pass 3: Removing '&': \n{deobfuscated_content}")
    
    output_filename = "a_dot_text_b64_blob_decoded_array_full_deobfuscated"
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(deobfuscated_content)
        print(f"\nStage 2: Fully deobfuscated and saved at '{output_filename}'")
    except IOError as e:
        print(f"\nError writing to file '{output_filename}': {e}")

```
---
## Final Payload Behavior

The final VBScript:

```vb
Set b=CreateObject("ADODB.Stream")
b.Type=2
b.CharSet="us-ascii"
b.Open
b.WriteText(CreateObject("WScript.Network").ComputerName)
b.Position=0
b.Type=1
b.Position=0
Set n=CreateObject("Msxml2.DOMDocument.3.0").CreateElement("base64")
n.dataType="bin.base64"
n.nodeTypedValue=b.Read

Set r=New RegExp

r.Pattern="^....................................$"
If Not r.Test(n.text)then WScript.Quit
End If

r.Pattern="^[MSy][FfK][ERT][yCM][efI][{31][KeN][jIS][Uol][z5j][}TR][DNV][4Qj][kY_][{Qw][Qz9][R{h][UF_][9Ns][l7W][SQI][lPb][9ZQ][QTJ][Y97][Ei3][IKL][x0U][iUX][FOE][QnU][xL8][RT_][lkL][d}q][9Sa]$"

If Not r.Test(n.text)then WScript.Quit
End If

r.Pattern="^[{Sp][F7H][R1t][CHG][ze5][1na][D7N][jGJ][U}r][kBj][RSq][ZEN][3WQ][k9q][Kw9][XzV][WkR][FLi][m94][HW2][dQT][r{l][9}t][tpT][B8Y][A13][TI0][M7x][EZU][yFb][Quh][BRx][TsA][kQJ][3Xd][r39]$"

If Not r.Test(n.text)then WScript.Quit
End If

r.Pattern="^[WoS][cFe][_yR][CzE][Xce][1HN][OYN][vTj][uDU][MYj][Rr7][GN4][tEQ][8kd][wnr][zpI][5Ra][F2x][9hP][xeW][9JQ][lRF][9ai][j7T][UVY][c3F][enI][fwx][vUH][xXF][Q1{][EVx][5TX][Fki][Zdw][of9]$"

If Not r.Test(n.text)then WScript.Quit
End If

MsgBox("Correct!")
```

Does the following:
1. Gets the computer name
2. base64 encodes it
3. Validates it using three complex regular expressions
4. Displays "Correct!" if all pass

## Flag Extraction

While with deeper visual inspection at the regular expression we can deduce the flag part by part by identifying the common character in each set.
For example for first char: `[MSy]`,  `[{Sp]`and `[WoS]` to be satisfied the first character needs to be `S` (the common in all three)

During the contest, we wrote a Z3 solver script that models each character as an 8-bit symbolic variable and applies constraints based on the regex patterns.

`solve-z3.py`:

```python
import base64
from z3 import BitVec, Solver, sat, Or

# Initialize 36 symbolic characters (ASCII)
chars = [BitVec(f'c{i}', 8) for i in range(36)]
s = Solver()

# Add Constraint: all characters must be printable ASCII
for c in chars:
    s.add(c >= ord('!'), c <= ord('~'))

def add_regex_constraint(pattern):
    pattern_body = pattern.strip("^$[]")
    for i, group in enumerate(pattern_body.split('][')):
        s.add(Or([chars[i] == ord(ch) for ch in group]))

# Patterns from the VBScript
patterns = [
    "^[MSy][FfK][ERT][yCM][efI][{31][KeN][jIS][Uol][z5j][}TR][DNV][4Qj][kY_][{Qw][Qz9][R{h][UF_][9Ns][l7W][SQI][lPb][9ZQ][QTJ][Y97][Ei3][IKL][x0U][iUX][FOE][QnU][xL8][RT_][lkL][d}q][9Sa]$",
    "^[{Sp][F7H][R1t][CHG][ze5][1na][D7N][jGJ][U}r][kBj][RSq][ZEN][3WQ][k9q][Kw9][XzV][WkR][FLi][m94][HW2][dQT][r{l][9}t][tpT][B8Y][A13][TI0][M7x][EZU][yFb][Quh][BRx][TsA][kQJ][3Xd][r39]$",
    "^[WoS][cFe][_yR][CzE][Xce][1HN][OYN][vTj][uDU][MYj][Rr7][GN4][tEQ][8kd][wnr][zpI][5Ra][F2x][9hP][xeW][9JQ][lRF][9ai][j7T][UVY][c3F][enI][fwx][vUH][xXF][Q1{][EVx][5TX][Fki][Zdw][of9]$"
]

# Add the RegEx constraints
for pat in patterns:
    add_regex_constraint(pat)

# Solve the constraints
if s.check() == sat:
    m = s.model()
    # result = ''.join([chr(m[c].as_long()) for c in chars])
    result = ''.join([chr(int(str(m[c]))) for c in chars])
    print(f"Valid base64 encoded computer name: {result}")

    try:
        decoded_result = base64.b64decode(result).decode('utf-8')
        print(f"Base64 decoded computer name: {decoded_result}")
    except Exception as e:
        print(f"Failed to decode: {e}")
else:
    print("No solution found.")
```

The solution:

```bash
$ python3 solve_z3-asif.py
Valid base64 encoded computer name: SFRCe1NjUjRNQkwzRF9WQl9TY3IxUFQxTkd9
Base64 decoded computer name: HTB{ScR4MBL3D_VB_Scr1PT1NG}
```

---
## Conclusion:

This challenge showcases a multi-layered VBScript obfuscation chain that leverages modular arithmetic, character encoding, and runtime execution to conceal its behavior.
We approach the problem methodically by:
- Extracting and decoding base64-encoded payloads
- Reversing obfuscation through custom Python scripts
- Using regular expressions to reconstruct character-level logic
- Employing symbolic solving via Z3 to recover the expanded base64-encoded value.

Through this process, we gain valuable insights into real-world obfuscation patterns and the power of automation in reverse engineering. Challenges like this emphasize the importance of scripting, pattern recognition, and constraint solving when dissecting obfuscated malware or payloads.

Overall, _Scrambled Payload_ was an enjoyable and educational reverse engineering task that sharpened both low-level inspection and high-level problem-solving skills.

---

**Author**: Asif Iqbal Gazi
**Event**: Business CTF 2025
