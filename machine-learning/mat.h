// ������ļ���Ҫ���ڹ��ڶ�ά��������Ĳ���
#ifndef __MAT_
#define __MAT_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
//#include <random>
#include <time.h>

#define full 0
#define same 1
#define valid 2

typedef struct Mat2DSize{
	int c; // �У���
	int r; // �У��ߣ�
}nSize;

float** rotate180(float** mat, nSize matSize);// ����ת180��

void addmat(float** res, float** mat1, nSize matSize1, float** mat2, nSize matSize2);// �������

float** correlation(float** map,nSize mapSize,float** inputData,nSize inSize,int type);// �����

float** cov(float** map,nSize mapSize,float** inputData,nSize inSize,int type); // �������

// ����Ǿ�����ϲ�������ֵ�ڲ壩��upc��upr���ڲ屶��
float** UpSample(float** mat,nSize matSize,int upc,int upr);

// ����ά�����Ե��������addw��С��0ֵ��
float** matEdgeExpand(float** mat,nSize matSize,int addc,int addr);

// ����ά�����Ե��С������shrinkc��С�ı�
float** matEdgeShrink(float** mat,nSize matSize,int shrinkc,int shrinkr);

void savemat(float** mat,nSize matSize,const char* filename);// �����������

void multifactor(float** res, float** mat, nSize matSize, float factor);// �������ϵ��

float summat(float** mat,nSize matSize);// �����Ԫ�صĺ�

char * combine_strings(char *a, char *b);

char* intTochar(int i);

#endif