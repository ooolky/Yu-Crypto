
// Yu-Crypto.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CYuCryptoApp:
// �йش����ʵ�֣������ Yu-Crypto.cpp
//

class CYuCryptoApp : public CWinApp
{
public:
	CYuCryptoApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CYuCryptoApp theApp;