
// ReleaseSingleton.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CReleaseSingletonApp: 
// �йش����ʵ�֣������ ReleaseSingleton.cpp
//

class CReleaseSingletonApp : public CWinApp
{
public:
	CReleaseSingletonApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CReleaseSingletonApp theApp;