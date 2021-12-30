
// Yu-CryptoDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Yu-Crypto.h"
#include "Yu-CryptoDlg.h"
#include "afxdialogex.h"
#include "Bigint.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

char m[1000] = { 0 };//明文
char c[1000] = { 0 };//密文
char M[1000] = { 0 };//解密得到的信息
int block = 0;//分块

bool SubKey[16][48];//子密钥16轮 48bit

//初始置换IP
const static char IP_Table[64] = {
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,
	64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7
};
//初始逆置换IP
const static char IP_N_Table[64] = {
	40,8,48,16,56,24,64,32,
	39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30,
	37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28,
	35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26,
	33,1,41,9,49,17,57,25
};
//扩展表E
static const char E_Table[48] = {
	//少打一行
	32,1,2,3,4,5,
	4,5,6,7,8,9,
	8,9,10,11,12,13,
	12,13,14,15,16,17,
	16,17,18,19,20,21,
	/**/20,21,22,23,24,25,
	24,25,26,27,28,29,
	28,29,30,31,32,1
};
//S盒
static const char S_Box[8][4][16] = {
	//S1第一行10书上是0待检验
	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
	0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
	4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
	15,12,8,2,4,9,1,7,5,11,3,15,10,0,6,13,	//15填成了14
	//S2
	15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
	 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
	 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
	13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
	//S3
	10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
	13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
	13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
	1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
	//S4
	7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
	13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
	10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
	3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
	//S5
	2, 12,4,1, 7, 10,11,6,8,5,3,15,13,0,14,9,
	14,11,2,12,4, 7, 13,1,5,0,15,10,3,9,8,6,
	4, 2, 1,11,10,13,7,8,15,9,12,5,6,3,0,14,
	11,8,12,7, 1, 14,2,13,6,15,0,9,10,4,5,3,
	//S6
	12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
	10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
	9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
	4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
	//S7
	4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
	13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
	1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
	6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
	//S8
	13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
	1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
	7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
	2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
};
//P盒
static const char P_Table[32] = {
	16,7,20,21,
	29,12,28,17,
	1,15,23,26, 
	5,18,31,10,
	2,8,24,14,
	32,27,3,9,
	19,13,30,6,
	22,11,4,25
};
//PC_1置换
static const char PC_1_Table[56] = {
	57,49,41,33,25,17,9,
	1,58,50,42,34,26,18,
	10,2,59,51,43,35,27,
	19,11,3,60,52,44,36,
	63,55,47,39,31,23,15,
	7,62,54,46,38,30,22,
	14,6,61,53,45,37,29,
	21,13,5,28,20,12,4
};
//PC_2置换
static const char PC_2_Table[48] = {
	14, 17, 11, 24,  1,  5, 
	3,  28, 15,  6, 21, 10, 
	23, 19, 12,  4, 26,  8, 
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 
	30, 40, 51, 45, 33, 48, 
	44, 49, 39, 56, 34, 53, 
	46, 42, 50, 36, 29, 32,
};
//左移位数表
static const char LS_Table[16] = {
	1, 1, 2, 2, 2, 2, 2, 2,
	1, 2, 2, 2, 2, 2, 2, 1
};

void Transform(bool* Out, bool* In, const char* Table, int len);//表置换
void Des_Run(char Out[8], char In[8], bool flag);//加解密函数，靠flag选择功能
void Des_SetSubkey(char key[8]);//生成子密钥
void F_func(bool In[32], bool Ki[48]);//F轮函数
void S_func(bool Out[32], bool In[48]);//S盒置换
void Xor(bool* InA, bool* InB, int len);//异或
void Rotatel(bool* In, int len, int loop);//循环左移
void ByteToBit(bool* Out, const char* In, int bits);//字符转比特
void HalfByteToBit(bool* Out, const char* In, int bits);//半字符转比特
void BitToByte(char* Out, const bool* In, int bits);//比特转字符

Bigint p = { 0 };
Bigint q = { 0 };
Bigint e = { 0 };
Bigint d = { 0 };
Bigint PhiN = { 0 };
Bigint N = { 0 };
Bigint cc = { 0 };
Bigint mm = { 0 };
Bigint MM = { 0 };

void Des_Run(char Out[8], char In[8], bool flag)
{
	static bool M[64];//存储64位明文，由明文字符转换得来
	static bool Temp[32];//中间变量，用于对Li赋值
	static bool* Li = &M[0];//分为左右两组
	static bool* Ri = &M[32];
	ByteToBit(M, In, 64);
	if (flag)
	{
		Transform(M, M, IP_Table, 64);//初始置换IP
		for (int i = 0; i < 16; i++)
		{
			memcpy(Temp, Ri, 32);//把R(i-1)保存起来
			F_func(Ri, SubKey[i]);
			Xor(Ri, Li, 32);
			memcpy(Li, Temp, 32);//Li=R(i-1)
		}
		memcpy(Temp, Li, 32);
		memcpy(Li, Ri, 32);
		memcpy(Ri, Temp, 32);//最后交换Li,Ri
		Transform(M, M, IP_N_Table, 64);

	}
	else {
		Transform(M, M, IP_Table, 64);
		for (int i = 15; i >= 0; i--)//没有等于0
		{
			memcpy(Temp, Ri, 32);//把R(i-1)保存起来
			F_func(Ri, SubKey[i]);
			Xor(Ri, Li, 32);
			memcpy(Li, Temp, 32);//Li=R(i-1)
		}
		memcpy(Temp, Li, 32);
		memcpy(Li, Ri, 32);
		memcpy(Ri, Temp, 32);//最后交换Li,Ri
		Transform(M, M, IP_N_Table, 64);
	}
	BitToByte(Out, M, 64);
}
void ByteToBit(bool* Out, const char* In, int bits)
{	
	//把各种盒或表里的十进制转成比特
	for (int i = 0; i < bits; i++)
	{
		Out[i] = (In[i / 8] >> (i % 8)) & 1;
	}
}
void HalfByteToBit(bool* Out, const char* In, int bits)//把各种盒或表里的十进制转成比特
{
	for (int i = 0; i < bits; i++)
	{
		Out[i] = (In[i /4] >> (i % 4)) & 1;
	}
}
void Transform(bool* Out, bool* In, const char* Table, int len)//置换
{
	bool Temp[256];
	for (int i = 0; i < len; i++)
	{
		//Out[i] = In[Table[i] - 1];//Table[i]-1，从0开始计数
		Temp[i] = In[Table[i] - 1];
	}
	memcpy(Out, Temp, len);
}
void F_func(bool In[32], bool Ki[48])
{
	static bool MR[48];
	Transform(MR, In, E_Table, 48);
	Xor(MR, Ki, 48);
	S_func(In, MR);
	Transform(In, In, P_Table,32);

}
void Xor(bool* InA, bool* InB, int len)
{
	for (int i = 0; i < len; i++)
		InA[i] = (InA[i] ^ InB[i]);
}
void S_func(bool Out[32], bool In[48])//错误写成了bool* Out[32]
{
	for (char i = 0, j, k; i < 8; i++)//
	{	
		j = (In[0+6*i] << 1) + In[5+6*i];//行等于首尾拼起来组成的十进制数
		k = (In[1+6*i] << 3) + (In[2+6*i] << 2) + (In[3+6*i] << 1) + In[4+6*i];
		HalfByteToBit(Out+4*i, &S_Box[i][j][k], 4);
	}
}
void BitToByte(char* Out, const bool* In, int bits)
{
	memset(Out, 0, bits >> 3);//初始化8个字节的内存
	for (int i = 0; i < bits; i++)
	{
		Out[i >> 3] |= In[i] << (i & 7);
	}
}

void Des_SetSubkey(char key[8])
{
	static bool K[64];
	static bool* KL = &K[0];
	static bool* KR = &K[28];
	ByteToBit(K, key, 64);
	Transform(K, K, PC_1_Table, 56);
	for (int i = 0; i < 16; i++)
	{
		Rotatel(KL, 28, LS_Table[i]);
		Rotatel(KR, 28, LS_Table[i]);
		Transform(SubKey[i], K, PC_2_Table,48);//忘记PC_2置换了

	}
}
void Rotatel(bool* In, int len, int loop)
{
	static bool Temp[28];
	memcpy(Temp, In, loop);//循环位loop位保存在temp中
	memcpy(In, In + loop, len - loop);//左移
	memcpy(In + len - loop, Temp, loop);//补上
}

void PrintNum(unsigned char *out,int &len, Bigint a)
{
	//修改
	len = 0;
	unsigned char temp[2000] = { 0 };
	//unsigned int temp[2000] = { 0 };
	Bigint b = { 0 };
	Bigint c = { 10 };
	while (Compare(a, b) == 1)			//a>0
	{
		temp[len] = Mod(a, c).num[0];
		a = Div(a, c);
		len++;
	}
	
	int j = 0;
	for (int i = len - 1; i >= 0; i--)
	{
		out[j] = temp[i];
		j++;
	}
}

Bigint GCD(Bigint a, Bigint b)		//辗转相除法
{
	Bigint c = { 0 };
	while (getLength(a) > 0)
	{
		Copy(c, Mod(b, a));
		Copy(b, a);
		Copy(a, c);
	}
	return b;
}
Bigint GenE(Bigint PhiN)			//生成公钥e
{
	Bigint e = BigRand(PhiN);		//e取1 - PhiN
	Bigint g = GCD(PhiN, e);
	while (getLength(g) != 1 || g.num[0] != 1)		//g是最大公因数，循环至g=1结束
	{
		e = BigRand(PhiN);
		g = GCD(PhiN, e);
	}
	return e;
}

bool GenD(Bigint e, Bigint PhiN, Bigint &d)
{
	if (Inverse(e, PhiN, d))
		return 1;
	else
		return 0;
}

Bigint Encrypt(Bigint m, Bigint e, Bigint n)
{
	return PowMod(m, e, n);

}
Bigint Decrypt(Bigint c, Bigint d, Bigint n)
{
	return PowMod(c, d, n);
}

//修改
CString CYuCryptoDlg::Tansform(unsigned char * Out, int len)		//返回CString,转成十进制输出
{
	CString res;
	CString Temp;
	for (int i = 0; i < len; i++)
	{
		Temp.Format(_T("%u"), Out[i]);
		res = res + Temp;
	}
	return res;
}


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CYuCryptoDlg 对话框




CYuCryptoDlg::CYuCryptoDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CYuCryptoDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CYuCryptoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CYuCryptoDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON2, &CYuCryptoDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_RADIO1, &CYuCryptoDlg::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CYuCryptoDlg::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_BUTTON1, &CYuCryptoDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_RADIO3, &CYuCryptoDlg::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_BUTTON3, &CYuCryptoDlg::OnBnClickedButton3)
	ON_EN_CHANGE(IDC_EDIT1, &CYuCryptoDlg::OnEnChangeEdit1)
	ON_EN_CHANGE(IDC_EDIT4, &CYuCryptoDlg::OnEnChangeEdit4)
END_MESSAGE_MAP()


// CYuCryptoDlg 消息处理程序

BOOL CYuCryptoDlg::OnInitDialog()
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CYuCryptoDlg::OnSysCommand(UINT nID, LPARAM lParam)
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
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CYuCryptoDlg::OnPaint()
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
HCURSOR CYuCryptoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CYuCryptoDlg::OnBnClickedButton1()
{
	int check_1 = ((CButton*)GetDlgItem(IDC_RADIO1))->GetCheck();//caeser
	int check_2 = ((CButton*)GetDlgItem(IDC_RADIO2))->GetCheck();//des
	int check_3 = ((CButton*)GetDlgItem(IDC_RADIO3))->GetCheck();//rsa
	
if(check_1==1)
{
	CString message;
	CString cipher;
	CString key;
	GetDlgItemText(IDC_EDIT2, message);//获取文本框内容传给message
	GetDlgItemText(IDC_EDIT1, key);//获取密钥文本框内容传给key
	char *message1 = message.GetBuffer(0);
	char *cipher1;
	int key1 = 0;
	int key2 = 0;
	key1 = _ttoi(key) % 26;//将cstring转换成int型
	key2 = _ttoi(key) % 10;
	cipher1 = message1;//默认密文等于明文
	int size = message.GetLength();
	for (int i = 0; i < size; i++)
	{
		if (message1[i] >= 'a'&&message1[i] <= 'z')//小写字母
		{
			if (message1[i] + key1 > 122)//122为‘z'的ascii码
			{
				cipher1[i] = message[i] + key1 - 26;
			}
			else 
			{
				cipher1[i] = message[i] + key1;
			}
		}
		if (message1[i] >= 'A'&&message1[i] <= 'Z')//大写字母
		{
			if (message1[i] + key1 > 90)//90为‘Z'的ascii码
			{
				cipher1[i] = message[i] + key1 - 26;
			}
			else
			{
				cipher1[i] = message[i] + key1;
			}
		}
		if (message1[i] >= '0'&&message[i] <= '9')
		{
			
			if (message1[i] + key2 > 57)//57为‘9'的ascii码
			{
				cipher1[i] = message[i] + key2 - 10;
			}
			else
			{
				cipher1[i] = message[i] + key2;
			}

		}
	}
	cipher = cipher1;
	SetDlgItemText(IDC_EDIT3, cipher);
}
else if(check_2==1)
{
	CString message;
	GetDlgItemText(IDC_EDIT2, message);//读入明文
	int size = message.GetLength();
	block = (size - 1) / 8 + 1;//分组长度,全局变量

	CString k;
	GetDlgItemText(IDC_EDIT1, k);
	char* key = k.GetBuffer(0);
	Des_SetSubkey(key);

	char m_block[8] = { 0 };//分组
	char c_block[8] = { 0 };

	for (int i = 0; i < block - 1; i++)//少加了等于
	{
		for (int j = 0; j < 8; j++)
			m_block[j] = message.GetAt(8 * i + j);//获取明文对应分组字符
		Des_Run(c_block, m_block, 1);
		for (int j = 0; j < 8; j++)
			c[8 * i + j] = c_block[j];//密文汇总
	}

	//最后一组填充并加密
	for (int j = 0; j < 8; j++)
		m_block[j] = 0;
	for (int j = 0; j < (size - 1) % 8 + 1; j++)
		m_block[j] = message.GetAt(8 * (block - 1) + j);
	Des_Run(c_block, m_block, 1);
	for (int j = 0; j < 8; j++)
		c[8 * (block - 1) + j] = c_block[j];//把j写成了1
	
	//显示密文
	CString cipher = c;
	SetDlgItemText(IDC_EDIT3, cipher);
}
else if(check_3==1)
{
	CString msg;
	GetDlgItemText(IDC_EDIT2, msg);
	char *message = msg.GetBuffer(0);
	int len = msg.GetLength();
	for (int i = 0; i < len; i++)
	{
		mm.num[i] = message[i];			//m全局变量，Bigint型,待检查中文是否可行
	}
	cc = Encrypt(mm, e, N);				//体现为什么用全局变量

	CString Temp;
	Temp.Format(_T("%s"), cc.num);
	SetDlgItemText(IDC_EDIT3, Temp);
}
}


void CYuCryptoDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	int check_1 = ((CButton*)GetDlgItem(IDC_RADIO1))->GetCheck();//caeser
	int check_2 = ((CButton*)GetDlgItem(IDC_RADIO2))->GetCheck();//des
	int check_3 = ((CButton*)GetDlgItem(IDC_RADIO3))->GetCheck();//rsa

if(check_1==1)
{
	CString message;
	CString cipher;
	CString key;
	GetDlgItemText(IDC_EDIT3, message);//获取文本框内容传给message
	GetDlgItemText(IDC_EDIT1, key);//获取密钥文本框内容传给key
	char *message1 = message.GetBuffer(0);
	char *cipher1;
	int key1 = 0;
	int key2 = 0;
	key1 = 26 - _ttoi(key) % 26;
	key2 = 10 - _ttoi(key) % 10;
	cipher1 = message1;//默认密文等于明文
	int size = message.GetLength();
	for (int i = 0; i < size; i++)
	{
		if (message1[i] >= 'a'&&message1[i] <= 'z')//小写字母
		{
			if (message1[i] + key1 > 122)//122为‘z'的ascii码
			{
				cipher1[i] = message[i] + key1 - 26;
			}
			else 
			{
				cipher1[i] = message[i] + key1;
			}
		}
		if (message1[i] >= 'A'&&message1[i] <= 'Z')//大写字母
		{
			if (message1[i] + key1 > 90)//90为‘Z'的ascii码
			{
				cipher1[i] = message[i] + key1 - 26;
			}
			else
			{
				cipher1[i] = message[i] + key1;
			}
		}
		if (message1[i] >= '0'&&message[i] <= '9')
		{
			
			if (message1[i] + key2 > 57)//57为‘9'的ascii码
			{
				cipher1[i] = message[i] + key2 - 10;
			}
			else
			{
				cipher1[i] = message[i] + key2;
			}

		}
	}
	cipher = cipher1;
	SetDlgItemText(IDC_EDIT2, cipher);
}
else if(check_2==1)
{
	char m_block[8] = { 0 };
	char c_block[8] = { 0 };
	//开始修改
	CString k;
	GetDlgItemText(IDC_EDIT1, k);
	char* key = k.GetBuffer(0);
	Des_SetSubkey(key);
	CString Cipher;
	GetDlgItemText(IDC_EDIT3, Cipher);
	block = Cipher.GetLength() / 8;//密文只能是8的整数倍

	for (int i = 0; i < block; i++)//block改成了8
	{
		for (int j = 0; j < 8; j++)
			c_block[j] = Cipher[8 * i + j];
		Des_Run(m_block, c_block, 0);
		for (int j = 0; j < 8; j++)
			M[8 * i + j] = m_block[j];
	}
	//显示解密文
	CString message = M;
	SetDlgItemText(IDC_EDIT2, message);
}
else if(check_3==1)
{
	MM = Decrypt(cc, d, N);
	CString Temp;
	Temp.Format(_T("%s"), MM.num);
	SetDlgItemText(IDC_EDIT2, Temp);
}
}

void CYuCryptoDlg::OnBnClickedButton3()
{
	int check_1 = ((CButton*)GetDlgItem(IDC_RADIO1))->GetCheck();//caeser
	int check_2 = ((CButton*)GetDlgItem(IDC_RADIO2))->GetCheck();//des
	int check_3 = ((CButton*)GetDlgItem(IDC_RADIO3))->GetCheck();//rsa

if(check_1==1||check_2==1)
{
	char pwdcont[]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	int i;
	int random;
	char *Password = (char *)malloc(12 + 1);
	
	srand((unsigned)time(NULL));
	for(i = 0;i < 12;i++)
	{
        random = rand()%(strlen(pwdcont));
		*(Password + i) = pwdcont[random]; 
	}
	
	*(Password + i)= '\0'; 

	SetDlgItemText(IDC_EDIT1,Password);

}
else if(check_3==1)
{
	// TODO: 在此添加控件通知处理程序代码
    //CString P, Q, N, E, D;
	//Bigint p, q, n, e, d;
	srand(time(NULL));
	p = GenPrime(16);			//先来 N 256比特
	q = GenPrime(16);				//SIZE越短，加密越快			//SIZE 65,512比特需要4分50秒,256比特3分多
	N = Narrow(Mul(p, q));				//SIZE 33 256比特 50s
	int len = 0;

	//修改
	
	unsigned char Out1[2000] = { 0 };
	unsigned char Out2[2000] = { 0 };
	unsigned char Out3[2000] = { 0 };
	unsigned char Out4[2000] = { 0 };
	unsigned char Out5[2000] = { 0 };
	/*
	unsigned int Out1[2000] = { 0 };
	unsigned int Out2[2000] = { 0 };
	unsigned int Out3[2000] = { 0 };
	unsigned int Out4[2000] = { 0 };
	unsigned int Out5[2000] = { 0 };*/
	CString res;
	//输出p
	PrintNum(Out1, len, p);
	res = CYuCryptoDlg::Tansform(Out1, len);		//自己定义的

	//输出q
	PrintNum(Out2, len, q);							//len传入之后会重置0
	res = CYuCryptoDlg::Tansform(Out2, len);		

	//输出N
	PrintNum(Out3, len, N);
	res = CYuCryptoDlg::Tansform(Out3, len);

	//生成e,输出e
	Bigint one = { 1 };
	PhiN = Narrow(Mul(Sub(p, one), Sub(q, one)));//计算PhiN
	e = GenE(PhiN);								//生成e
	PrintNum(Out4, len, e);
	res = CYuCryptoDlg::Tansform(Out4, len);
	SetDlgItemText(IDC_EDIT4, res);

	//生成d,输出d
	Inverse(e, PhiN, d);
	PrintNum(Out5, len, d);
	res = CYuCryptoDlg::Tansform(Out5, len);
	SetDlgItemText(IDC_EDIT1, res);
}
}


void CYuCryptoDlg::OnBnClickedRadio1()
{
	// TODO: 在此添加控件通知处理程序代码
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(FALSE);
	SetDlgItemText(IDC_EDIT1, "");
	SetDlgItemText(IDC_EDIT2, "");
	SetDlgItemText(IDC_EDIT3, "");
	SetDlgItemText(IDC_EDIT4, "");
}


void CYuCryptoDlg::OnBnClickedRadio2()
{
	// TODO: 在此添加控件通知处理程序代码
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(FALSE);
	SetDlgItemText(IDC_EDIT1, "");
	SetDlgItemText(IDC_EDIT2, "");
	SetDlgItemText(IDC_EDIT3, "");
	SetDlgItemText(IDC_EDIT4, "");
}


void CYuCryptoDlg::OnBnClickedRadio3()
{
	// TODO: 在此添加控件通知处理程序代码
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(TRUE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(TRUE);
	SetDlgItemText(IDC_EDIT1, "");
	SetDlgItemText(IDC_EDIT2, "");
	SetDlgItemText(IDC_EDIT3, "");
	SetDlgItemText(IDC_EDIT4, "");
}


void CYuCryptoDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CYuCryptoDlg::OnEnChangeEdit4()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}
