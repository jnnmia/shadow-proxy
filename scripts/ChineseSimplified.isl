; *** Inno Setup version 6.x 简体中文语言包 ***
; 适用环境: Inno Setup 6 Unicode (UTF-8 编码)

[LangOptions]
LanguageName=简体中文
LanguageID=$0804
LanguageCodePage=0

[Messages]
SetupAppTitle=安装向导
SetupWindowTitle=%1 安装向导
UninstallAppTitle=卸载
UninstallAppFullTitle=%1 卸载

; 通用弹窗
InformationTitle=信息
ConfirmTitle=确认
ErrorTitle=错误

; 按钮文本
ButtonBack=< 上一步(&B)
ButtonNext=下一步(&N) >
ButtonInstall=安装(&I)
ButtonOK=确定
ButtonCancel=取消
ButtonReset=重置(&R)
ButtonHelp=帮助(&H)
ButtonClose=关闭(&C)
ButtonFinish=完成(&F)
ButtonYes=是(&Y)
ButtonYesToAll=全是(&A)
ButtonNo=否(&N)
ButtonNoToAll=全否(&O)

; 欢迎页面
WelcomeLabel1=欢迎使用 [name] 安装向导
WelcomeLabel2=向导将在您的计算机上安装 [name/ver]。%n%n建议您在继续之前关闭所有其它应用程序。

; 目标位置选择
WizardSelectDir=选择安装目标位置
SelectDirDesc=您希望将 [name] 安装到什么位置？
SelectDirLabel3=安装程序将把 [name] 安装到以下文件夹。
SelectDirBrowseLabel=单击“下一步”继续。如果您想选择其它文件夹，请单击“浏览”。
DiskSpaceGBLabel=至少需要 [gb] GB 的可用磁盘空间。
DiskSpaceMBLabel=至少需要 [mb] MB 的可用磁盘空间。
CannotInstallToNetworkDrive=安装程序无法安装到网络驱动器。
CannotInstallToUNCPath=安装程序无法安装到 UNC 路径。
InvalidPath=您必须输入包含盘符的完整路径；例如：%n%nC:\APP%n%n或者 UNC 路径形如：%n%n\\server\share
InvalidDrive=您选择的驱动器或 UNC 共享不存在或无法访问。请重新选择。
DiskSpaceWarningTitle=磁盘空间不足
DiskSpaceWarning=安装程序至少需要 %1 KB 的可用磁盘空间，但所选驱动器仅有 %2 KB 可用。%n%n您仍要继续吗？
DirExistsTitle=文件夹已存在
DirExists=文件夹：%n%n%1%n%n已经存在。您仍要安装到该文件夹吗？
DirDoesntExistTitle=文件夹不存在
DirDoesntExist=文件夹：%n%n%1%n%n不存在。您想要创建此文件夹吗？

; 附加任务页面
WizardSelectTasks=选择附加任务
SelectTasksDesc=您想要执行哪些附加任务？
SelectTasksLabel2=选择您想要安装程序在安装 [name] 时执行的附加任务，然后单击“下一步”。

; 准备安装
WizardReady=准备安装
ReadyLabel1=安装程序现在准备开始在您的计算机上安装 [name]。
ReadyLabel2a=单击“安装”继续安装，如果您想查看或更改任何设置，请单击“上一步”。

; 正在安装
WizardInstalling=正在安装
InstallingLabel=安装程序正在将 [name] 安装到您的计算机中，请稍候。
StatusCreateDirs=正在创建目录...
StatusExtractFiles=正在解压缩文件...
StatusCreateIcons=正在创建快捷方式...
StatusCreateIniEntries=正在创建 INI 条目...
StatusCreateRegistryEntries=正在创建注册表项...
StatusRegisterFiles=正在注册文件...
StatusSavingVersionCreation=正在保存版本信息...

; 准备就绪与完成
WizardFinished=完成 [name] 安装向导
FinishedHeadingLabel=[name] 安装向导完成
FinishedLabelNoIcons=安装程序已在您的计算机上完成了 [name] 的安装。
FinishedLabel=安装程序已在您的计算机上完成了 [name] 的安装。可以通过选择已安装的图标来运行该应用程序。
ClickFinish=单击“完成”退出安装向导。

; 卸载页面
ConfirmUninstall=您确定要完全删除 %1 及其所有组件吗？
UninstallStatusLabel=正在从您的计算机中删除 %1，请稍候。
UninstalledAll=%1 已成功从您的计算机中删除。
UninstallOnlyOnWin64=此安装程序仅能在 64 位 Windows 上卸载。
OnlyAdminCanUninstall=必须具有管理员权限才能卸载此程序。
UninstallNotFound=文件“%1”不存在。无法卸载。
