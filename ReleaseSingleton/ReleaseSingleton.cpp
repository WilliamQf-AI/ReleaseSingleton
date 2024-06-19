
// ReleaseSingleton.cpp : ����Ӧ�ó��������Ϊ��
//

#include "stdafx.h"
#include "ReleaseSingleton.h"
#include "ReleaseSingletonDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CReleaseSingletonApp

BEGIN_MESSAGE_MAP(CReleaseSingletonApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CReleaseSingletonApp ����

CReleaseSingletonApp::CReleaseSingletonApp()
{
	// ֧����������������
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: �ڴ˴���ӹ�����룬
	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��
}


// Ψһ��һ�� CReleaseSingletonApp ����

CReleaseSingletonApp theApp;


// CReleaseSingletonApp ��ʼ��
BOOL IsAdmin(void);
BOOL CReleaseSingletonApp::InitInstance()
{
	// ���һ�������� Windows XP �ϵ�Ӧ�ó����嵥ָ��Ҫ
	// ʹ�� ComCtl32.dll �汾 6 ����߰汾�����ÿ��ӻ���ʽ��
	//����Ҫ InitCommonControlsEx()��  ���򣬽��޷��������ڡ�
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// ��������Ϊ��������Ҫ��Ӧ�ó�����ʹ�õ�
	// �����ؼ��ࡣ
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	if (!IsAdmin()){
		MessageBox(nullptr, L"���Թ���ԱȨ�����б�����", nullptr, MB_OK);
		return 0;
	}

	// ���� shell ���������Է��Ի������
	// �κ� shell ����ͼ�ؼ��� shell �б���ͼ�ؼ���
	CShellManager *pShellManager = new CShellManager;

	// ���Windows Native���Ӿ����������Ա��� MFC �ؼ�����������
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// ��׼��ʼ��
	// ���δʹ����Щ���ܲ�ϣ����С
	// ���տ�ִ���ļ��Ĵ�С����Ӧ�Ƴ�����
	// ����Ҫ���ض���ʼ������
	// �������ڴ洢���õ�ע�����
	// TODO: Ӧ�ʵ��޸ĸ��ַ�����
	// �����޸�Ϊ��˾����֯��
	SetRegistryKey(_T("Ӧ�ó��������ɵı���Ӧ�ó���"));

	CReleaseSingletonDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: �ڴ˷��ô����ʱ��
		//  ��ȷ�������رնԻ���Ĵ���
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: �ڴ˷��ô����ʱ��
		//  ��ȡ�������رնԻ���Ĵ���
	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "����: �Ի��򴴽�ʧ�ܣ�Ӧ�ó���������ֹ��\n");
		TRACE(traceAppMsg, 0, "����: ������ڶԻ�����ʹ�� MFC �ؼ������޷� #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS��\n");
	}

	// ɾ�����洴���� shell ��������
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

#ifndef _AFXDLL
	ControlBarCleanUp();
#endif

	// ���ڶԻ����ѹرգ����Խ����� FALSE �Ա��˳�Ӧ�ó���
	//  ����������Ӧ�ó������Ϣ�á�
	return FALSE;
}

BOOL IsAdmin(void)
{
	HANDLE                   hAccessToken;
	BYTE                     InfoBuffer[1024]{ 0 };
	PTOKEN_GROUPS            ptgGroups;
	DWORD                    dwInfoBufferSize;
	PSID                     psidAdministrators;
	SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
	UINT                     i;
	BOOL                     bRet = FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hAccessToken))
		return bRet;

	bRet = GetTokenInformation(hAccessToken, TokenGroups, InfoBuffer, 1024, &dwInfoBufferSize);
	CloseHandle(hAccessToken);
	if (!bRet)
		return bRet;

	if (!AllocateAndInitializeSid(&siaNtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&psidAdministrators))
		return FALSE;
	bRet = FALSE;
	ptgGroups = (PTOKEN_GROUPS)InfoBuffer;
	for (i = 0; i < ptgGroups->GroupCount; ++i)
	{
		if (EqualSid(psidAdministrators, ptgGroups->Groups[i].Sid))
			bRet = TRUE;
	}

	FreeSid(psidAdministrators);
	return bRet;
}

