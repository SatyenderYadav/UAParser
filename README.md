# UAParser

#### What is UserAssist Artifacts ?

This is the artifacts which is inside the NTUSER.DAT file [ HKCU Registry ]. It will contain the information about  what programs are executed inside the system.

#### Where UserAssist is located ?
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\`

#### Infomration provided by Artifact:

- This can provide which program is executed on system.
- Provide the detail if the program is `executed via lnk or the executable`.
- Provide the `number of times` the program is executed.
- Provide the the last `Modification Time`
- Also provide the details like focus seconds of the executed program, path of the exectubale or lnk.

#### Usage

```py 
python3 main.py -f <Exported HKCU>
```

#### Result

![tool_ua](https://user-images.githubusercontent.com/54953623/217026635-3665335e-7f4c-46ae-b250-4abf025b945d.PNG)

#### References

[Program Execution Analysis using UserAssist Key in Modern Window](https://www.scitepress.org/papers/2017/64167/64167.pdf)

[Windows 7 UserAssist Registry Keys Analysis](https://intotheboxes.files.wordpress.com/2010/04/intotheboxes_2010_q1.pdf)

[Windows userassist keys](https://www.aldeid.com/wiki/Windows-userassist-keys)


