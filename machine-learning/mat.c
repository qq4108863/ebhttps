#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
//#include <random>
#include <time.h>
#include "mat.h"

float** rotate180(float** mat, nSize matSize)// ����ת180��
{
	int i,c,r;
	int outSizeW=matSize.c;
	int outSizeH=matSize.r;
	float** outputData=(float**)malloc(outSizeH*sizeof(float*));
	for(i=0;i<outSizeH;i++)
		outputData[i]=(float*)malloc(outSizeW*sizeof(float));

	for(r=0;r<outSizeH;r++)
		for(c=0;c<outSizeW;c++)
			outputData[r][c]=mat[outSizeH-r-1][outSizeW-c-1];

	return outputData;
}

// ���ھ������ز��������ѡ��
// ���ﹲ������ѡ��full��same��valid���ֱ��ʾ
// fullָ��ȫ�����������Ĵ�СΪinSize+(mapSize-1)
// sameָͬ������ͬ��С
// validָ��ȫ������Ĵ�С��һ��ΪinSize-(mapSize-1)��С���䲻��Ҫ��������0����

float** correlation(float** map,nSize mapSize,float** inputData,nSize inSize,int type)// �����
{
	// ����Ļ�������ں��򴫲�ʱ���ã������ڽ�Map��ת180���پ��
	// Ϊ�˷�����㣬�����Ƚ�ͼ������һȦ
	// ����ľ��Ҫ�ֳ�������ż��ģ��ͬ����ģ��
	int i,j,c,r;
	int halfmapsizew;
	int halfmapsizeh;
	if(mapSize.r%2==0&&mapSize.c%2==0){ // ģ���СΪż��
		halfmapsizew=(mapSize.c)/2; // ���ģ��İ���С
		halfmapsizeh=(mapSize.r)/2;
	}else{
		halfmapsizew=(mapSize.c-1)/2; // ���ģ��İ���С
		halfmapsizeh=(mapSize.r-1)/2;
	}

	// ������Ĭ�Ͻ���fullģʽ�Ĳ�����fullģʽ�������СΪinSize+(mapSize-1)
	int outSizeW=inSize.c+(mapSize.c-1); // ������������һ����
	int outSizeH=inSize.r+(mapSize.r-1);
	float** outputData=(float**)malloc(outSizeH*sizeof(float*)); // ����صĽ��������
	for(i=0;i<outSizeH;i++)
		outputData[i]=(float*)calloc(outSizeW,sizeof(float));

	// Ϊ�˷�����㣬��inputData����һȦ
	float** exInputData=matEdgeExpand(inputData,inSize,mapSize.c-1,mapSize.r-1);

	for(j=0;j<outSizeH;j++)
		for(i=0;i<outSizeW;i++)
			for(r=0;r<mapSize.r;r++)
				for(c=0;c<mapSize.c;c++){
					outputData[j][i]=outputData[j][i]+map[r][c]*exInputData[j+r][i+c];
				}

	for(i=0;i<inSize.r+2*(mapSize.r-1);i++)
		free(exInputData[i]);
	free(exInputData);

	nSize outSize={outSizeW,outSizeH};
	switch(type){ // ���ݲ�ͬ����������ز�ͬ�Ľ��
	case full: // ��ȫ��С�����
		return outputData;
	case same:{
		float** sameres=matEdgeShrink(outputData,outSize,halfmapsizew,halfmapsizeh);
		for(i=0;i<outSize.r;i++)
			free(outputData[i]);
		free(outputData);
		return sameres;
		}
	case valid:{
		float** validres;
		if(mapSize.r%2==0&&mapSize.c%2==0)
			validres=matEdgeShrink(outputData,outSize,halfmapsizew*2-1,halfmapsizeh*2-1);
		else
			validres=matEdgeShrink(outputData,outSize,halfmapsizew*2,halfmapsizeh*2);
		for(i=0;i<outSize.r;i++)
			free(outputData[i]);
		free(outputData);
		return validres;
		}
	default:
		return outputData;
	}
}

float** cov(float** map,nSize mapSize,float** inputData,nSize inSize,int type) // �������
{
	// ���������������ת180�ȵ�����ģ���������
	float** flipmap=rotate180(map,mapSize); //��ת180�ȵ�����ģ��
	float** res=correlation(flipmap,mapSize,inputData,inSize,type);
	int i;
	for(i=0;i<mapSize.r;i++)
		free(flipmap[i]);
	free(flipmap);
	return res;
}

// ����Ǿ�����ϲ�������ֵ�ڲ壩��upc��upr���ڲ屶��
float** UpSample(float** mat,nSize matSize,int upc,int upr)
{ 
	int i,j,m,n;
	int c=matSize.c;
	int r=matSize.r;
	float** res=(float**)malloc((r*upr)*sizeof(float*)); // ����ĳ�ʼ��
	for(i=0;i<(r*upr);i++)
		res[i]=(float*)malloc((c*upc)*sizeof(float));

	for(j=0;j<r*upr;j=j+upr){
		for(i=0;i<c*upc;i=i+upc)// �������
			for(m=0;m<upc;m++)
				res[j][i+m]=mat[j/upr][i/upc];

		for(n=1;n<upr;n++)      //  �ߵ�����
			for(i=0;i<c*upc;i++)
				res[j+n][i]=res[j][i];
	}
	return res;
}

// ����ά�����Ե��������addw��С��0ֵ��
float** matEdgeExpand(float** mat,nSize matSize,int addc,int addr)
{ // ������Ե����
	int i,j;
	int c=matSize.c;
	int r=matSize.r;
	float** res=(float**)malloc((r+2*addr)*sizeof(float*)); // ����ĳ�ʼ��
	for(i=0;i<(r+2*addr);i++)
		res[i]=(float*)malloc((c+2*addc)*sizeof(float));

	for(j=0;j<r+2*addr;j++){
		for(i=0;i<c+2*addc;i++){
			if(j<addr||i<addc||j>=(r+addr)||i>=(c+addc))
				res[j][i]=(float)0.0;
			else
				res[j][i]=mat[j-addr][i-addc]; // ����ԭ����������
		}
	}
	return res;
}

// ����ά�����Ե��С������shrinkc��С�ı�
float** matEdgeShrink(float** mat,nSize matSize,int shrinkc,int shrinkr)
{ // ��������С������Сaddw������Сaddh
	int i,j;
	int c=matSize.c;
	int r=matSize.r;
	float** res=(float**)malloc((r-2*shrinkr)*sizeof(float*)); // �������ĳ�ʼ��
	for(i=0;i<(r-2*shrinkr);i++)
		res[i]=(float*)malloc((c-2*shrinkc)*sizeof(float));

	
	for(j=0;j<r;j++){
		for(i=0;i<c;i++){
			if(j>=shrinkr&&i>=shrinkc&&j<(r-shrinkr)&&i<(c-shrinkc))
				res[j-shrinkr][i-shrinkc]=mat[j][i]; // ����ԭ����������
		}
	}
	return res;
}

void savemat(float** mat,nSize matSize,const char* filename)
{
	FILE  *fp=NULL;
	fp=fopen(filename,"wb");
	if(fp==NULL)
		printf("write file failed\n");

	int i;
	for(i=0;i<matSize.r;i++)
		fwrite(mat[i],sizeof(float),matSize.c,fp);
	fclose(fp);
}

void addmat(float** res, float** mat1, nSize matSize1, float** mat2, nSize matSize2)// �������
{
	int i,j;
	if(matSize1.c!=matSize2.c||matSize1.r!=matSize2.r)
		printf("ERROR: Size is not same!");

	for(i=0;i<matSize1.r;i++)
		for(j=0;j<matSize1.c;j++)
			res[i][j]=mat1[i][j]+mat2[i][j];
}

void multifactor(float** res, float** mat, nSize matSize, float factor)// �������ϵ��
{
	int i,j;
	for(i=0;i<matSize.r;i++)
		for(j=0;j<matSize.c;j++)
			res[i][j]=mat[i][j]*factor;
}

float summat(float** mat,nSize matSize) // �����Ԫ�صĺ�
{
	float sum=0.0;
	int i,j;
	for(i=0;i<matSize.r;i++)
		for(j=0;j<matSize.c;j++)
			sum=sum+mat[i][j];
	return sum;
}