
// ReleaseSingletonDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "ReleaseSingleton.h"
#include "ReleaseSingletonDlg.h"
#include "afxdialogex.h"

#include <tchar.h>
#include <iostream>
#include <psapi.h>
#include <string>

#include <TlHelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#pragma comment(lib, "Psapi.lib")

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CReleaseSingletonDlg 对话框



CReleaseSingletonDlg::CReleaseSingletonDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_RELEASESINGLETON_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CReleaseSingletonDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CReleaseSingletonDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CReleaseSingletonDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CReleaseSingletonDlg 消息处理程序

BOOL CReleaseSingletonDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	SetDlgItemTextW(IDC_EDIT1, L"Global\\ZDR_DATARECOVERY_SINGLE"); 
	SetDlgItemTextW(IDC_EDIT2, L"ZDataRecovery.exe"); 

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CReleaseSingletonDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CReleaseSingletonDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CReleaseSingletonDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// 获取进程ID
DWORD GetProcessIdByName(const TCHAR* processName) {
	DWORD processIds[1024], cbNeeded, cProcesses;
	if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
		return 0;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (unsigned int i = 0; i < cProcesses; i++) {
		if (processIds[i] != 0) {
			TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);

			if (hProcess) {
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
					GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
				}
			}
			CloseHandle(hProcess);

			if (_tcsicmp(szProcessName, processName) == 0) {
				return processIds[i];
			}
		}
	}

	return 0;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	TCHAR* MutexName = (TCHAR*)lpParameter;
	HANDLE hMutex(OpenMutex(SYNCHRONIZE, FALSE, MutexName));
	if (hMutex) {
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
		hMutex = nullptr;
	}
	return 0;
}


// 注入代码释放互斥量
bool InjectAndCloseMutex(DWORD processId, const TCHAR* mutexName) {
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
	if (hProcess == NULL) {
		std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
		return false;
	}
#if 0
	// 在目标进程中分配内存
	LPVOID pRemoteMutexName = VirtualAllocEx(hProcess, NULL, (_tcslen(mutexName) + 1) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteMutexName == NULL) {
		std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return false;
	}

	// 将互斥量名称写入目标进程的内存
	if (!WriteProcessMemory(hProcess, pRemoteMutexName, (LPVOID)mutexName, (_tcslen(mutexName) + 1) * sizeof(TCHAR), NULL)) {
		std::cerr << "Failed to write memory in target process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMutexName, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 定义要注入的代码：打开和关闭互斥量
	const char code[] =
		"\x55"                            // push ebp
		"\x8B\xEC"                        // mov ebp, esp
		"\x83\xEC\x0C"                    // sub esp, 12h
		"\x68\x00\x00\x00\x00"            // push offset of mutex name (to be fixed up)
		"\xFF\x15\x00\x00\x00\x00"        // call [OpenMutexW]
		"\x50"                            // push eax
		"\xFF\x15\x00\x00\x00\x00"        // call [ReleaseMutex]
		"\xFF\x15\x00\x00\x00\x00"        // call [CloseHandle]
		"\xC9"                            // leave
		"\xC2\x04\x00";                   // ret 4

										  // 在目标进程中分配内存
	LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pRemoteCode == NULL) {
		std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMutexName, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 写入代码到目标进程
	if (!WriteProcessMemory(hProcess, pRemoteCode, code, sizeof(code), NULL)) {
		std::cerr << "Failed to write memory in target process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMutexName, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 获取所需函数的地址
	FARPROC pOpenMutex = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "OpenMutexW");
	FARPROC pReleaseMutex = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "ReleaseMutex");
	FARPROC pCloseHandle = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "CloseHandle");

	if (!pOpenMutex || !pReleaseMutex || !pCloseHandle) {
		std::cerr << "Failed to get addresses of required functions." << std::endl;
		VirtualFreeEx(hProcess, pRemoteMutexName, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 修正注入代码中的地址
	SIZE_T bytesWritten;
	DWORD oldProtect;
	VirtualProtectEx(hProcess, pRemoteCode, sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(hProcess, (LPVOID)((char*)pRemoteCode + 1), &pRemoteMutexName, sizeof(LPVOID), &bytesWritten);
	WriteProcessMemory(hProcess, (LPVOID)((char*)pRemoteCode + 6), &pOpenMutex, sizeof(LPVOID), &bytesWritten);
	WriteProcessMemory(hProcess, (LPVOID)((char*)pRemoteCode + 12), &pReleaseMutex, sizeof(LPVOID), &bytesWritten);
	WriteProcessMemory(hProcess, (LPVOID)((char*)pRemoteCode + 18), &pCloseHandle, sizeof(LPVOID), &bytesWritten);
	VirtualProtectEx(hProcess, pRemoteCode, sizeof(code), oldProtect, &oldProtect);
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL); 
#else
	// 在目标进程的地址空间中分配内存
	LPVOID pRemoteThreadProc = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 线程函数
	SIZE_T bytesWritten;
	WriteProcessMemory(hProcess, pRemoteThreadProc, &ThreadProc, 4096, &bytesWritten);
	// 创建远程线程来执行注入的代码
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc, (void*)mutexName, 0, NULL);
#endif
	if (hThread == NULL) {
		std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteThreadProc, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// 等待线程执行完毕
	WaitForSingleObject(hThread, INFINITE);

	// 清理
	//VirtualFreeEx(hProcess, pRemoteMutexName, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pRemoteThreadProc, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}

int t1(const std::wstring&MutexName) {
	if (MutexName.empty())
		return 0;

	const TCHAR* targetProcessName = _T("ZDataRecovery_d.exe");

	DWORD processId = GetProcessIdByName(targetProcessName);
	if (processId == 0) {
		HANDLE hProcessSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return FALSE;

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);
		BOOL bProcess(Process32First(hProcessSnap, &pe32));
		TCHAR buff[1024 + 1]{ 0 };
		while (bProcess) {
			if (_tcsicmp(targetProcessName, pe32.szExeFile) == 0) {
				processId = pe32.th32ProcessID;
				break;
			}
			memset(buff, 0x00, 1024);
			bProcess = Process32Next(hProcessSnap, &pe32);
		}
		if (processId == 0)
			return 0;
	}

	if (InjectAndCloseMutex(processId, MutexName.c_str())) {
		std::cout << "Mutex released successfully." << std::endl;
	}
	else {
		std::cerr << "Failed to release mutex." << std::endl;
	}

	return 1;
}

void t2(const std::wstring&MutexName, HANDLE hProc) {
	if (MutexName.empty())
		return;

	HANDLE hMutex(OpenMutex(SYNCHRONIZE, FALSE, MutexName.c_str()));
	if (hMutex) {
		ReleaseMutex(hMutex);
		DuplicateHandle(hProc, hMutex, NULL, 0, 0, false, DUPLICATE_CLOSE_SOURCE);
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
		hMutex = nullptr;
	}
}

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

using NTSTATUS = long;
typedef NTSTATUS(*_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(*_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(*_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

void ErrorExit(LPTSTR lpszFunction) {
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	

	LocalFree(lpMsgBuf);
	ExitProcess(dw);
}

void ShowErr() {
	CHAR errormsg[100];
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, errormsg, sizeof(errormsg), NULL);
	printf("ERROR: %s", errormsg);
}

bool t3(const std::wstring&MutexName, const std::wstring& ProcessName) {
	if (MutexName.empty() || ProcessName.empty())
		return false;

	int ipos = MutexName.find(L"\\");
	const std::wstring FindName(MutexName.substr(ipos + 1, MutexName.length() - ipos - 1));

	_NtQuerySystemInformation NtQuerySystemInformation = (decltype(NtQuerySystemInformation))GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (decltype(NtDuplicateObject))GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (decltype(NtQueryObject))GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;

	ULONG pid = GetProcessIdByName(ProcessName.c_str());
	if (pid == 0) {
		HANDLE hProcessSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return FALSE;

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);
		BOOL bProcess(Process32First(hProcessSnap, &pe32));
		TCHAR buff[1024 + 1]{ 0 };
		while (bProcess) {
			if (_tcsicmp(ProcessName.c_str(), pe32.szExeFile) == 0) {
				pid = pe32.th32ProcessID;
				break;
			}
			memset(buff, 0x00, 1024);
			bProcess = Process32Next(hProcessSnap, &pe32);
		}
	}

	if (pid == 0) {
		::MessageBox(nullptr, L"请先启动目标程序！", nullptr, MB_OK);
		return FALSE;
	}

	if (!(processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid))) {
		printf("Could not open PID %d! (Don't try to open a system process.)\n", pid);
		return FALSE;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size.
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
	if (!NT_SUCCESS(status)) {
		printf("NtQuerySystemInformation failed!\n");
		return FALSE;
	}

	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		// Check if this handle belongs to the PID the user specified.
		if (handle.ProcessId != pid)
			continue;

		// Duplicate the handle so we can query it.
		if (!NT_SUCCESS(NtDuplicateObject(
			processHandle,
			(void*)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0
		))) {

			printf("[%#x] Error!\n", handle.Handle);
			continue;
		}

		// Query the object type.
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		))) {

			printf("[%#x] Error!\n", handle.Handle);
			CloseHandle(dupHandle);
			continue;
		}

		// Query the object name (unless it has an access of
		//   0x0012019f, on which NtQueryObject could hang.
		if (handle.GrantedAccess == 0x0012019f) {

			// We have the type, so display that.
			printf(
				"[%#x] %.*S: (did not get name)\n",
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
			);

			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectNameInformation,
			objectNameInfo,
			0x1000,
			&returnLength
		))) {

			// Reallocate the buffer and try again.
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				returnLength,
				NULL
			))) {

				// We have the type name, so just display that.
				printf(
					"[%#x] %.*S: (could not get name)\n",
					handle.Handle,
					objectTypeInfo->Name.Length / 2,
					objectTypeInfo->Name.Buffer
				);

				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}

		// Cast our buffer into an UNICODE_STRING.
		objectName = *(PUNICODE_STRING)objectNameInfo;

		// Print the information!
		if (objectName.Length)
		{
			if (_tcsicmp(L"Mutant", objectTypeInfo->Name.Buffer) == 0) {
				objectName.Length = objectName.Length;
			}
			const std::wstring content(objectName.Buffer); 
			if (content.rfind(FindName) != -1) {
				ReleaseMutex((HANDLE)handle.Handle);
				::DuplicateHandle(processHandle, (HANDLE)handle.Handle, ::GetCurrentProcess(), &dupHandle,
					0, FALSE, DUPLICATE_CLOSE_SOURCE);
				ReleaseMutex((HANDLE)handle.Handle);
				::CloseHandle(dupHandle);
				break;
			}
			// The object has a name.
			printf(
				"[%#x] %.*S: %.*S\n",
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer,
				objectName.Length / 2,
				objectName.Buffer
			);
		}
		else {
			// Print something else.
			printf(
				"[%#x] %.*S: (unnamed)\n",
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
			);
		}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}

	free(handleInfo); 
	CloseHandle(processHandle);

	return TRUE;
}

void CReleaseSingletonDlg::OnBnClickedOk()
{
	TCHAR MutexName[MAX_PATH]{ 0 }, ProcessName[MAX_PATH]{ 0 };
	GetDlgItemTextW(IDC_EDIT1, MutexName, MAX_PATH);
	if (wcslen(MutexName) <= 0)
		return;

	GetDlgItemTextW(IDC_EDIT2, ProcessName, MAX_PATH);
	if (wcslen(ProcessName) <= 0)
		return;

	if (t3(MutexName, ProcessName)) {
		MessageBox(L"解除成功！", nullptr, MB_OK);
		CDialogEx::OnOK();
	}
}

