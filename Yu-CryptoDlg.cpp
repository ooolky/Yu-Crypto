
// Yu-CryptoDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "Yu-Crypto.h"
#include "Yu-CryptoDlg.h"
#include "afxdialogex.h"
#include "Bigint.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

char m[1000] = { 0 };//����
char c[1000] = { 0 };//����
char M[1000] = { 0 };//���ܵõ�����Ϣ
int block = 0;//�ֿ�

bool SubKey[16][48];//����Կ16�� 48bit

//��ʼ�û�IP
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
//��ʼ���û�IP
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
//��չ��E
static const char E_Table[48] = {
	//�ٴ�һ��
	32,1,2,3,4,5,
	4,5,6,7,8,9,
	8,9,10,11,12,13,
	12,13,14,15,16,17,
	16,17,18,19,20,21,
	/**/20,21,22,23,24,25,
	24,25,26,27,28,29,
	28,29,30,31,32,1
};
//S��
static const char S_Box[8][4][16] = {
	//S1��һ��10������0������
	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
	0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
	4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
	15,12,8,2,4,9,1,7,5,11,3,15,10,0,6,13,	//15�����14
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
//P��
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
//PC_1�û�
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
//PC_2�û�
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
//����λ����
static const char LS_Table[16] = {
	1, 1, 2, 2, 2, 2, 2, 2,
	1, 2, 2, 2, 2, 2, 2, 1
};

void Transform(bool* Out, bool* In, const char* Table, int len);//���û�
void Des_Run(char Out[8], char In[8], bool flag);//�ӽ��ܺ�������flagѡ����
void Des_SetSubkey(char key[8]);//��������Կ
void F_func(bool In[32], bool Ki[48]);//F�ֺ���
void S_func(bool Out[32], bool In[48]);//S���û�
void Xor(bool* InA, bool* InB, int len);//���
void Rotatel(bool* In, int len, int loop);//ѭ������
void ByteToBit(bool* Out, const char* In, int bits);//�ַ�ת����
void HalfByteToBit(bool* Out, const char* In, int bits);//���ַ�ת����
void BitToByte(char* Out, const bool* In, int bits);//����ת�ַ�

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
	static bool M[64];//�洢64λ���ģ��������ַ�ת������
	static bool Temp[32];//�м���������ڶ�Li��ֵ
	static bool* Li = &M[0];//��Ϊ��������
	static bool* Ri = &M[32];
	ByteToBit(M, In, 64);
	if (flag)
	{
		Transform(M, M, IP_Table, 64);//��ʼ�û�IP
		for (int i = 0; i < 16; i++)
		{
			memcpy(Temp, Ri, 32);//��R(i-1)��������
			F_func(Ri, SubKey[i]);
			Xor(Ri, Li, 32);
			memcpy(Li, Temp, 32);//Li=R(i-1)
		}
		memcpy(Temp, Li, 32);
		memcpy(Li, Ri, 32);
		memcpy(Ri, Temp, 32);//��󽻻�Li,Ri
		Transform(M, M, IP_N_Table, 64);

	}
	else {
		Transform(M, M, IP_Table, 64);
		for (int i = 15; i >= 0; i--)//û�е���0
		{
			memcpy(Temp, Ri, 32);//��R(i-1)��������
			F_func(Ri, SubKey[i]);
			Xor(Ri, Li, 32);
			memcpy(Li, Temp, 32);//Li=R(i-1)
		}
		memcpy(Temp, Li, 32);
		memcpy(Li, Ri, 32);
		memcpy(Ri, Temp, 32);//��󽻻�Li,Ri
		Transform(M, M, IP_N_Table, 64);
	}
	BitToByte(Out, M, 64);
}
void ByteToBit(bool* Out, const char* In, int bits)
{	
	//�Ѹ��ֺл�����ʮ����ת�ɱ���
	for (int i = 0; i < bits; i++)
	{
		Out[i] = (In[i / 8] >> (i % 8)) & 1;
	}
}
void HalfByteToBit(bool* Out, const char* In, int bits)//�Ѹ��ֺл�����ʮ����ת�ɱ���
{
	for (int i = 0; i < bits; i++)
	{
		Out[i] = (In[i /4] >> (i % 4)) & 1;
	}
}
void Transform(bool* Out, bool* In, const char* Table, int len)//�û�
{
	bool Temp[256];
	for (int i = 0; i < len; i++)
	{
		//Out[i] = In[Table[i] - 1];//Table[i]-1����0��ʼ����
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
void S_func(bool Out[32], bool In[48])//����д����bool* Out[32]
{
	for (char i = 0, j, k; i < 8; i++)//
	{	
		j = (In[0+6*i] << 1) + In[5+6*i];//�е�����βƴ������ɵ�ʮ������
		k = (In[1+6*i] << 3) + (In[2+6*i] << 2) + (In[3+6*i] << 1) + In[4+6*i];
		HalfByteToBit(Out+4*i, &S_Box[i][j][k], 4);
	}
}
void BitToByte(char* Out, const bool* In, int bits)
{
	memset(Out, 0, bits >> 3);//��ʼ��8���ֽڵ��ڴ�
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
		Transform(SubKey[i], K, PC_2_Table,48);//����PC_2�û���

	}
}
void Rotatel(bool* In, int len, int loop)
{
	static bool Temp[28];
	memcpy(Temp, In, loop);//ѭ��λloopλ������temp��
	memcpy(In, In + loop, len - loop);//����
	memcpy(In + len - loop, Temp, loop);//����
}

void PrintNum(unsigned char *out,int &len, Bigint a)
{
	//�޸�
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

Bigint GCD(Bigint a, Bigint b)		//շת�����
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
Bigint GenE(Bigint PhiN)			//���ɹ�Կe
{
	Bigint e = BigRand(PhiN);		//eȡ1 - PhiN
	Bigint g = GCD(PhiN, e);
	while (getLength(g) != 1 || g.num[0] != 1)		//g�����������ѭ����g=1����
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

//�޸�
CString CYuCryptoDlg::Tansform(unsigned char * Out, int len)		//����CString,ת��ʮ�������
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


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CYuCryptoDlg �Ի���




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


// CYuCryptoDlg ��Ϣ�������

BOOL CYuCryptoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(FALSE);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CYuCryptoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
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
	GetDlgItemText(IDC_EDIT2, message);//��ȡ�ı������ݴ���message
	GetDlgItemText(IDC_EDIT1, key);//��ȡ��Կ�ı������ݴ���key
	char *message1 = message.GetBuffer(0);
	char *cipher1;
	int key1 = 0;
	int key2 = 0;
	key1 = _ttoi(key) % 26;//��cstringת����int��
	key2 = _ttoi(key) % 10;
	cipher1 = message1;//Ĭ�����ĵ�������
	int size = message.GetLength();
	for (int i = 0; i < size; i++)
	{
		if (message1[i] >= 'a'&&message1[i] <= 'z')//Сд��ĸ
		{
			if (message1[i] + key1 > 122)//122Ϊ��z'��ascii��
			{
				cipher1[i] = message[i] + key1 - 26;
			}
			else 
			{
				cipher1[i] = message[i] + key1;
			}
		}
		if (message1[i] >= 'A'&&message1[i] <= 'Z')//��д��ĸ
		{
			if (message1[i] + key1 > 90)//90Ϊ��Z'��ascii��
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
			
			if (message1[i] + key2 > 57)//57Ϊ��9'��ascii��
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
	GetDlgItemText(IDC_EDIT2, message);//��������
	int size = message.GetLength();
	block = (size - 1) / 8 + 1;//���鳤��,ȫ�ֱ���

	CString k;
	GetDlgItemText(IDC_EDIT1, k);
	char* key = k.GetBuffer(0);
	Des_SetSubkey(key);

	char m_block[8] = { 0 };//����
	char c_block[8] = { 0 };

	for (int i = 0; i < block - 1; i++)//�ټ��˵���
	{
		for (int j = 0; j < 8; j++)
			m_block[j] = message.GetAt(8 * i + j);//��ȡ���Ķ�Ӧ�����ַ�
		Des_Run(c_block, m_block, 1);
		for (int j = 0; j < 8; j++)
			c[8 * i + j] = c_block[j];//���Ļ���
	}

	//���һ����䲢����
	for (int j = 0; j < 8; j++)
		m_block[j] = 0;
	for (int j = 0; j < (size - 1) % 8 + 1; j++)
		m_block[j] = message.GetAt(8 * (block - 1) + j);
	Des_Run(c_block, m_block, 1);
	for (int j = 0; j < 8; j++)
		c[8 * (block - 1) + j] = c_block[j];//��jд����1
	
	//��ʾ����
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
		mm.num[i] = message[i];			//mȫ�ֱ�����Bigint��,����������Ƿ����
	}
	cc = Encrypt(mm, e, N);				//����Ϊʲô��ȫ�ֱ���

	CString Temp;
	Temp.Format(_T("%s"), cc.num);
	SetDlgItemText(IDC_EDIT3, Temp);
}
}


void CYuCryptoDlg::OnBnClickedButton2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int check_1 = ((CButton*)GetDlgItem(IDC_RADIO1))->GetCheck();//caeser
	int check_2 = ((CButton*)GetDlgItem(IDC_RADIO2))->GetCheck();//des
	int check_3 = ((CButton*)GetDlgItem(IDC_RADIO3))->GetCheck();//rsa

if(check_1==1)
{
	CString message;
	CString cipher;
	CString key;
	GetDlgItemText(IDC_EDIT3, message);//��ȡ�ı������ݴ���message
	GetDlgItemText(IDC_EDIT1, key);//��ȡ��Կ�ı������ݴ���key
	char *message1 = message.GetBuffer(0);
	char *cipher1;
	int key1 = 0;
	int key2 = 0;
	key1 = 26 - _ttoi(key) % 26;
	key2 = 10 - _ttoi(key) % 10;
	cipher1 = message1;//Ĭ�����ĵ�������
	int size = message.GetLength();
	for (int i = 0; i < size; i++)
	{
		if (message1[i] >= 'a'&&message1[i] <= 'z')//Сд��ĸ
		{
			if (message1[i] + key1 > 122)//122Ϊ��z'��ascii��
			{
				cipher1[i] = message[i] + key1 - 26;
			}
			else 
			{
				cipher1[i] = message[i] + key1;
			}
		}
		if (message1[i] >= 'A'&&message1[i] <= 'Z')//��д��ĸ
		{
			if (message1[i] + key1 > 90)//90Ϊ��Z'��ascii��
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
			
			if (message1[i] + key2 > 57)//57Ϊ��9'��ascii��
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
	//��ʼ�޸�
	CString k;
	GetDlgItemText(IDC_EDIT1, k);
	char* key = k.GetBuffer(0);
	Des_SetSubkey(key);
	CString Cipher;
	GetDlgItemText(IDC_EDIT3, Cipher);
	block = Cipher.GetLength() / 8;//����ֻ����8��������

	for (int i = 0; i < block; i++)//block�ĳ���8
	{
		for (int j = 0; j < 8; j++)
			c_block[j] = Cipher[8 * i + j];
		Des_Run(m_block, c_block, 0);
		for (int j = 0; j < 8; j++)
			M[8 * i + j] = m_block[j];
	}
	//��ʾ������
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
	// TODO: �ڴ���ӿؼ�֪ͨ����������
    //CString P, Q, N, E, D;
	//Bigint p, q, n, e, d;
	srand(time(NULL));
	p = GenPrime(16);			//���� N 256����
	q = GenPrime(16);				//SIZEԽ�̣�����Խ��			//SIZE 65,512������Ҫ4��50��,256����3�ֶ�
	N = Narrow(Mul(p, q));				//SIZE 33 256���� 50s
	int len = 0;

	//�޸�
	
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
	//���p
	PrintNum(Out1, len, p);
	res = CYuCryptoDlg::Tansform(Out1, len);		//�Լ������

	//���q
	PrintNum(Out2, len, q);							//len����֮�������0
	res = CYuCryptoDlg::Tansform(Out2, len);		

	//���N
	PrintNum(Out3, len, N);
	res = CYuCryptoDlg::Tansform(Out3, len);

	//����e,���e
	Bigint one = { 1 };
	PhiN = Narrow(Mul(Sub(p, one), Sub(q, one)));//����PhiN
	e = GenE(PhiN);								//����e
	PrintNum(Out4, len, e);
	res = CYuCryptoDlg::Tansform(Out4, len);
	SetDlgItemText(IDC_EDIT4, res);

	//����d,���d
	Inverse(e, PhiN, d);
	PrintNum(Out5, len, d);
	res = CYuCryptoDlg::Tansform(Out5, len);
	SetDlgItemText(IDC_EDIT1, res);
}


void CYuCryptoDlg::OnBnClickedRadio1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(FALSE);
	SetDlgItemText(IDC_EDIT1, "");
	SetDlgItemText(IDC_EDIT2, "");
	SetDlgItemText(IDC_EDIT3, "");
	SetDlgItemText(IDC_EDIT4, "");
}


void CYuCryptoDlg::OnBnClickedRadio2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(FALSE);
	SetDlgItemText(IDC_EDIT1, "");
	SetDlgItemText(IDC_EDIT2, "");
	SetDlgItemText(IDC_EDIT3, "");
	SetDlgItemText(IDC_EDIT4, "");
}


void CYuCryptoDlg::OnBnClickedRadio3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	((CButton*)GetDlgItem(IDC_BUTTON3))->EnableWindow(TRUE);
	((CButton*)GetDlgItem(IDC_EDIT4))->EnableWindow(TRUE);
	SetDlgItemText(IDC_EDIT1, "");
	SetDlgItemText(IDC_EDIT2, "");
	SetDlgItemText(IDC_EDIT3, "");
	SetDlgItemText(IDC_EDIT4, "");
}


void CYuCryptoDlg::OnEnChangeEdit1()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}


void CYuCryptoDlg::OnEnChangeEdit4()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}
