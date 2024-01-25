#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
//#include <random.h>
#include <time.h>
#include "cnn.h"

char* intTochar(int i)// ������ת�����ַ���
{
	int itemp=i;
	int w=0;
	while(itemp>=10){
		itemp=itemp/10;
		w++;
	}
	char* ptr=(char*)malloc((w+2)*sizeof(char));
	ptr[w+1]='\0';
	int r; // ����
	while(i>=10){
		r=i%10;
		i=i/10;		
		ptr[w]=(char)(r+48);
		w--;
	}
	ptr[w]=(char)(i+48);
	return ptr;
}
char * combine_strings(char *a, char *b) // �������ַ�������
{
	char *ptr;
	int lena=strlen(a),lenb=strlen(b);
	int i,l=0;
	ptr = (char *)malloc((lena+lenb+1) * sizeof(char));
	for(i=0;i<lena;i++)
		ptr[l++]=a[i];
	for(i=0;i<lenb;i++)
		ptr[l++]=b[i];
	ptr[l]='\0';
	return(ptr);
}


void cnnsetup(CNN* cnn,nSize inputSize,int outputSize)
{
	cnn->layerNum=5;

	nSize inSize;
	int mapSize=5;
	inSize.c=inputSize.c;
	inSize.r=inputSize.r;
	cnn->C1=initCovLayer(inSize.c,inSize.r,5,1,6);
	inSize.c=inSize.c-mapSize+1;
	inSize.r=inSize.r-mapSize+1;
	cnn->S2=initPoolLayer(inSize.c,inSize.r,2,6,6,AvePool);
	inSize.c=inSize.c/2;
	inSize.r=inSize.r/2;
	cnn->C3=initCovLayer(inSize.c,inSize.r,5,6,12);
	inSize.c=inSize.c-mapSize+1;
	inSize.r=inSize.r-mapSize+1;
	cnn->S4=initPoolLayer(inSize.c,inSize.r,2,12,12,AvePool);
	inSize.c=inSize.c/2;
	inSize.r=inSize.r/2;
	cnn->O5=initOutLayer(inSize.c*inSize.r*12,outputSize);

	cnn->e=(float*)calloc(cnn->O5->outputNum,sizeof(float));
}

CovLayer* initCovLayer(int inputWidth,int inputHeight,int mapSize,int inChannels,int outChannels)
{
	CovLayer* covL=(CovLayer*)malloc(sizeof(CovLayer));

	covL->inputHeight=inputHeight;
	covL->inputWidth=inputWidth;
	covL->mapSize=mapSize;

	covL->inChannels=inChannels;
	covL->outChannels=outChannels;

	covL->isFullConnect=true; // Ĭ��Ϊȫ����

	// Ȩ�ؿռ�ĳ�ʼ�����������е��ã�[r][c]
	int i,j,c,r;
	srand((unsigned)time(NULL));
	covL->mapData=(float****)malloc(inChannels*sizeof(float***));
	for(i=0;i<inChannels;i++){
		covL->mapData[i]=(float***)malloc(outChannels*sizeof(float**));
		for(j=0;j<outChannels;j++){
			covL->mapData[i][j]=(float**)malloc(mapSize*sizeof(float*));
			for(r=0;r<mapSize;r++){
				covL->mapData[i][j][r]=(float*)malloc(mapSize*sizeof(float));
				for(c=0;c<mapSize;c++){
					float randnum=(((float)rand()/(float)RAND_MAX)-0.5)*2; 
					covL->mapData[i][j][r][c]=randnum*sqrt((float)6.0/(float)(mapSize*mapSize*(inChannels+outChannels)));
				}
			}
		}
	}
	// Ȩ���ݶȱ仯
	covL->dmapData=(float****)malloc(inChannels*sizeof(float***));
	for(i=0;i<inChannels;i++){
		covL->dmapData[i]=(float***)malloc(outChannels*sizeof(float**));
		for(j=0;j<outChannels;j++){
			covL->dmapData[i][j]=(float**)malloc(mapSize*sizeof(float*));
			for(r=0;r<mapSize;r++){
				covL->dmapData[i][j][r]=(float*)calloc(mapSize,sizeof(float));
			}
		}
	}

	covL->basicData=(float*)calloc(outChannels,sizeof(float));

	int outW=inputWidth-mapSize+1;
	int outH=inputHeight-mapSize+1;


	covL->d=(float***)malloc(outChannels*sizeof(float**));
	covL->v=(float***)malloc(outChannels*sizeof(float**));
	covL->y=(float***)malloc(outChannels*sizeof(float**));
	for(j=0;j<outChannels;j++){
		covL->d[j]=(float**)malloc(outH*sizeof(float*));
		covL->v[j]=(float**)malloc(outH*sizeof(float*));
		covL->y[j]=(float**)malloc(outH*sizeof(float*));
		for(r=0;r<outH;r++){
			covL->d[j][r]=(float*)calloc(outW,sizeof(float));
			covL->v[j][r]=(float*)calloc(outW,sizeof(float));
			covL->y[j][r]=(float*)calloc(outW,sizeof(float));
		}
	}

	return covL;
}

PoolLayer* initPoolLayer(int inputWidth,int inputHeight,int mapSize,int inChannels,int outChannels,int poolType)
{
	PoolLayer* poolL=(PoolLayer*)malloc(sizeof(PoolLayer));

	poolL->inputHeight=inputHeight;
	poolL->inputWidth=inputWidth;
	poolL->mapSize=mapSize;
	poolL->inChannels=inChannels;
	poolL->outChannels=outChannels;
	poolL->poolType=poolType; 

	poolL->basicData=(float*)calloc(outChannels,sizeof(float));

	int outW=inputWidth/mapSize;
	int outH=inputHeight/mapSize;

	int j,r;
	poolL->d=(float***)malloc(outChannels*sizeof(float**));
	poolL->y=(float***)malloc(outChannels*sizeof(float**));
	for(j=0;j<outChannels;j++){
		poolL->d[j]=(float**)malloc(outH*sizeof(float*));
		poolL->y[j]=(float**)malloc(outH*sizeof(float*));
		for(r=0;r<outH;r++){
			poolL->d[j][r]=(float*)calloc(outW,sizeof(float));
			poolL->y[j][r]=(float*)calloc(outW,sizeof(float));
		}
	}

	return poolL;
}

OutLayer* initOutLayer(int inputNum,int outputNum)
{
	OutLayer* outL=(OutLayer*)malloc(sizeof(OutLayer));

	outL->inputNum=inputNum;
	outL->outputNum=outputNum;


	outL->basicData=(float*)calloc(outputNum,sizeof(float));

	outL->d=(float*)calloc(outputNum,sizeof(float));
	outL->v=(float*)calloc(outputNum,sizeof(float));
	outL->y=(float*)calloc(outputNum,sizeof(float));

	// Ȩ�صĳ�ʼ��
	outL->wData=(float**)malloc(outputNum*sizeof(float*)); // �����У������
	int i,j;
	srand((unsigned)time(NULL));
	for(i=0;i<outputNum;i++){
		outL->wData[i]=(float*)malloc(inputNum*sizeof(float));
		for(j=0;j<inputNum;j++){
			float randnum=(((float)rand()/(float)RAND_MAX)-0.5)*2; // ����һ��-1��1�������
			outL->wData[i][j]=randnum*sqrt((float)6.0/(float)(inputNum+outputNum));
		}
	}

	outL->isFullConnect=true;

	return outL;
}

int vecmaxIndex(float* vec, int veclength)// ������������������
{
	int i;
	float maxnum=-1.0;
	int maxIndex=0;
	for(i=0;i<veclength;i++){
		if(maxnum<vec[i]){
			maxnum=vec[i];
			maxIndex=i;
		}
	}
	return maxIndex;
}

// ����cnn����
float cnntest(CNN* cnn, ImgArr inputData,LabelArr outputData,int testNum)
{
	int n=0;
	int incorrectnum=0;  //����Ԥ�����Ŀ
	for(n=0;n<testNum;n++){
		cnnff(cnn,inputData->ImgPtr[n].ImgData);
		if(vecmaxIndex(cnn->O5->y,cnn->O5->outputNum)!=vecmaxIndex(outputData->LabelPtr[n].LabelData,cnn->O5->outputNum))
			incorrectnum++;
		cnnclear(cnn);
	}
	return (float)incorrectnum/(float)testNum;
}

// ����cnn
void savecnn(CNN* cnn, const char* filename)
{
	FILE  *fp=NULL;
	fp=fopen(filename,"wb");
	if(fp==NULL)
		printf("write file failed\n");

	int i,j,r;
	// C1������
	for(i=0;i<cnn->C1->inChannels;i++)
		for(j=0;j<cnn->C1->outChannels;j++)
			for(r=0;r<cnn->C1->mapSize;r++)
				fwrite(cnn->C1->mapData[i][j][r],sizeof(float),cnn->C1->mapSize,fp);

	fwrite(cnn->C1->basicData,sizeof(float),cnn->C1->outChannels,fp);

	// C3����
	for(i=0;i<cnn->C3->inChannels;i++)
		for(j=0;j<cnn->C3->outChannels;j++)
			for(r=0;r<cnn->C3->mapSize;r++)
				fwrite(cnn->C3->mapData[i][j][r],sizeof(float),cnn->C3->mapSize,fp);

	fwrite(cnn->C3->basicData,sizeof(float),cnn->C3->outChannels,fp);

	// O5�����
	for(i=0;i<cnn->O5->outputNum;i++)
		fwrite(cnn->O5->wData[i],sizeof(float),cnn->O5->inputNum,fp);
	fwrite(cnn->O5->basicData,sizeof(float),cnn->O5->outputNum,fp);

	fclose(fp);
}
// ����cnn������
void importcnn(CNN* cnn, const char* filename)
{
	FILE  *fp=NULL;
	fp=fopen(filename,"rb");
	if(fp==NULL)
		printf("write file failed\n");

	int i,j,c,r;
	// C1������
	for(i=0;i<cnn->C1->inChannels;i++)
		for(j=0;j<cnn->C1->outChannels;j++)
			for(r=0;r<cnn->C1->mapSize;r++)
				for(c=0;c<cnn->C1->mapSize;c++){
					float* in=(float*)malloc(sizeof(float));
					fread(in,sizeof(float),1,fp);
					cnn->C1->mapData[i][j][r][c]=*in;
				}

	for(i=0;i<cnn->C1->outChannels;i++)
		fread(&cnn->C1->basicData[i],sizeof(float),1,fp);

	// C3����
	for(i=0;i<cnn->C3->inChannels;i++)
		for(j=0;j<cnn->C3->outChannels;j++)
			for(r=0;r<cnn->C3->mapSize;r++)
				for(c=0;c<cnn->C3->mapSize;c++)
				fread(&cnn->C3->mapData[i][j][r][c],sizeof(float),1,fp);

	for(i=0;i<cnn->C3->outChannels;i++)
		fread(&cnn->C3->basicData[i],sizeof(float),1,fp);

	// O5�����
	for(i=0;i<cnn->O5->outputNum;i++)
		for(j=0;j<cnn->O5->inputNum;j++)
			fread(&cnn->O5->wData[i][j],sizeof(float),1,fp);

	for(i=0;i<cnn->O5->outputNum;i++)
		fread(&cnn->O5->basicData[i],sizeof(float),1,fp);

	fclose(fp);
}

void cnntrain(CNN* cnn,	ImgArr inputData,LabelArr outputData,CNNOpts opts,int trainNum)
{
	// ѧϰѵ���������
	cnn->L=(float*)malloc(trainNum*sizeof(float));
	int e;
	for(e=0;e<opts.numepochs;e++){
		int n=0;
		for(n=0;n<trainNum;n++){
			//printf("%d\n",n);
			cnnff(cnn,inputData->ImgPtr[n].ImgData);  // ǰ�򴫲���������Ҫ�����
			cnnbp(cnn,outputData->LabelPtr[n].LabelData); // ���򴫲���������Ҫ�������Ԫ������ݶ�


			char* filedir="E:\\Code\\Matlab\\PicTrans\\CNNData\\";
			const char* filename=combine_strings(filedir,combine_strings(intTochar(n),".cnn"));
			savecnndata(cnn,filename,inputData->ImgPtr[n].ImgData);
			cnnapplygrads(cnn,opts,inputData->ImgPtr[n].ImgData); // ����Ȩ��

			cnnclear(cnn);
			// ���㲢�����������
			float l=0.0;
			int i;
			for(i=0;i<cnn->O5->outputNum;i++)
				l=l+cnn->e[i]*cnn->e[i];
			if(n==0)
				cnn->L[n]=l/(float)2.0;
			else
				cnn->L[n]=cnn->L[n-1]*0.99+0.01*l/(float)2.0;
		}
	}
}

// ����InputData��ͼ�����ݣ�inputData[r][c],r��c�У��������Ȩ��ģ����һ�µ�
void cnnff(CNN* cnn,float** inputData)
{
	int outSizeW=cnn->S2->inputWidth;
	int outSizeH=cnn->S2->inputHeight;
	// ��һ��Ĵ���
	int i,j,r,c;
	// ��һ���������
	nSize mapSize={cnn->C1->mapSize,cnn->C1->mapSize};
	nSize inSize={cnn->C1->inputWidth,cnn->C1->inputHeight};
	nSize outSize={cnn->S2->inputWidth,cnn->S2->inputHeight};
	for(i=0;i<(cnn->C1->outChannels);i++){
		for(j=0;j<(cnn->C1->inChannels);j++){
			float** mapout=cov(cnn->C1->mapData[j][i],mapSize,inputData,inSize,valid);
			addmat(cnn->C1->v[i],cnn->C1->v[i],outSize,mapout,outSize);
			for(r=0;r<outSize.r;r++)
				free(mapout[r]);
			free(mapout);
		}
		for(r=0;r<outSize.r;r++)
			for(c=0;c<outSize.c;c++)
				cnn->C1->y[i][r][c]=activation_Sigma(cnn->C1->v[i][r][c],cnn->C1->basicData[i]);
	}

	// �ڶ�����������S2��������
	outSize.c=cnn->C3->inputWidth;
	outSize.r=cnn->C3->inputHeight;
	inSize.c=cnn->S2->inputWidth;
	inSize.r=cnn->S2->inputHeight;
	for(i=0;i<(cnn->S2->outChannels);i++){
		if(cnn->S2->poolType==AvePool)
			avgPooling(cnn->S2->y[i],outSize,cnn->C1->y[i],inSize,cnn->S2->mapSize);
	}

	// �������������,������ȫ����
	outSize.c=cnn->S4->inputWidth;
	outSize.r=cnn->S4->inputHeight;
	inSize.c=cnn->C3->inputWidth;
	inSize.r=cnn->C3->inputHeight;
	mapSize.c=cnn->C3->mapSize;
	mapSize.r=cnn->C3->mapSize;
	for(i=0;i<(cnn->C3->outChannels);i++){
		for(j=0;j<(cnn->C3->inChannels);j++){
			float** mapout=cov(cnn->C3->mapData[j][i],mapSize,cnn->S2->y[j],inSize,valid);
			addmat(cnn->C3->v[i],cnn->C3->v[i],outSize,mapout,outSize);
			for(r=0;r<outSize.r;r++)
				free(mapout[r]);
			free(mapout);
		}
		for(r=0;r<outSize.r;r++)
			for(c=0;c<outSize.c;c++)
				cnn->C3->y[i][r][c]=activation_Sigma(cnn->C3->v[i][r][c],cnn->C3->basicData[i]);
	}

	// ���Ĳ���������
	inSize.c=cnn->S4->inputWidth;
	inSize.r=cnn->S4->inputHeight;
	outSize.c=inSize.c/cnn->S4->mapSize;
	outSize.r=inSize.r/cnn->S4->mapSize;
	for(i=0;i<(cnn->S4->outChannels);i++){
		if(cnn->S4->poolType==AvePool)
			avgPooling(cnn->S4->y[i],outSize,cnn->C3->y[i],inSize,cnn->S4->mapSize);
	}

	// �����O5�Ĵ���
	// ������Ҫ��ǰ��Ķ�ά���չ����һά����
	float* O5inData=(float*)malloc((cnn->O5->inputNum)*sizeof(float)); 
	for(i=0;i<(cnn->S4->outChannels);i++)
		for(r=0;r<outSize.r;r++)
			for(c=0;c<outSize.c;c++)
				O5inData[i*outSize.r*outSize.c+r*outSize.c+c]=cnn->S4->y[i][r][c];

	nSize nnSize={cnn->O5->inputNum,cnn->O5->outputNum};
	nnff(cnn->O5->v,O5inData,cnn->O5->wData,cnn->O5->basicData,nnSize);
	for(i=0;i<cnn->O5->outputNum;i++)
		cnn->O5->y[i]=activation_Sigma(cnn->O5->v[i],cnn->O5->basicData[i]);
	free(O5inData);
}

// ����� input�����ݣ�inputNum˵��������Ŀ��bas����ƫ��
float activation_Sigma(float input,float bas) // sigma�����
{
	float temp=input+bas;
	return (float)1.0/((float)(1.0+exp(-temp)));
}

void avgPooling(float** output,nSize outputSize,float** input,nSize inputSize,int mapSize) // ��ƽ��ֵ
{
	int outputW=inputSize.c/mapSize;
	int outputH=inputSize.r/mapSize;
	if(outputSize.c!=outputW||outputSize.r!=outputH)
		printf("ERROR: output size is wrong!!");

	int i,j,m,n;
	for(i=0;i<outputH;i++)
		for(j=0;j<outputW;j++)
		{
			float sum=0.0;
			for(m=i*mapSize;m<i*mapSize+mapSize;m++)
				for(n=j*mapSize;n<j*mapSize+mapSize;n++)
					sum=sum+input[m][n];

			output[i][j]=sum/(float)(mapSize*mapSize);
		}
}

// ����ȫ�����������ǰ�򴫲�
float vecMulti(float* vec1,float* vec2,int vecL)// ���������
{
	int i;
	float m=0;
	for(i=0;i<vecL;i++)
		m=m+vec1[i]*vec2[i];
	return m;
}

void nnff(float* output,float* input,float** wdata,float* bas,nSize nnSize)
{
	int w=nnSize.c;
	int h=nnSize.r;
	
	int i;
	for(i=0;i<h;i++)
		output[i]=vecMulti(input,wdata[i],w)+bas[i];
}

float sigma_derivation(float y){ // Logic��������Ա���΢��
	return y*(1-y); // ����y��ָ��������������ֵ���������Ա���
}

void cnnbp(CNN* cnn,float* outputData) // ����ĺ��򴫲�
{
	int i,j,c,r; // �����浽������
	for(i=0;i<cnn->O5->outputNum;i++)
		cnn->e[i]=cnn->O5->y[i]-outputData[i];

	/*�Ӻ���ǰ�������*/
	// �����O5
	for(i=0;i<cnn->O5->outputNum;i++)
		cnn->O5->d[i]=cnn->e[i]*sigma_derivation(cnn->O5->y[i]);

	// S4�㣬���ݵ�S4������
	// ����û�м����
	nSize outSize={cnn->S4->inputWidth/cnn->S4->mapSize,cnn->S4->inputHeight/cnn->S4->mapSize};
	for(i=0;i<cnn->S4->outChannels;i++)
		for(r=0;r<outSize.r;r++)
			for(c=0;c<outSize.c;c++)
				for(j=0;j<cnn->O5->outputNum;j++){
					int wInt=i*outSize.c*outSize.r+r*outSize.c+c;
					cnn->S4->d[i][r][c]=cnn->S4->d[i][r][c]+cnn->O5->d[j]*cnn->O5->wData[j][wInt];
				}

	// C3��
	// ��S4�㴫�ݵĸ��������,����ֻ����S4���ݶ�������һ��
	int mapdata=cnn->S4->mapSize;
	nSize S4dSize={cnn->S4->inputWidth/cnn->S4->mapSize,cnn->S4->inputHeight/cnn->S4->mapSize};
	// �����Pooling����ƽ�������Է��򴫵ݵ���һ��Ԫ������ݶ�û�б仯
	for(i=0;i<cnn->C3->outChannels;i++){
		float** C3e=UpSample(cnn->S4->d[i],S4dSize,cnn->S4->mapSize,cnn->S4->mapSize);
		for(r=0;r<cnn->S4->inputHeight;r++)
			for(c=0;c<cnn->S4->inputWidth;c++)
				cnn->C3->d[i][r][c]=C3e[r][c]*sigma_derivation(cnn->C3->y[i][r][c])/(float)(cnn->S4->mapSize*cnn->S4->mapSize);
		for(r=0;r<cnn->S4->inputHeight;r++)
			free(C3e[r]);
		free(C3e);
	}

	// S2�㣬S2��û�м����������ֻ�о�����м��������
	// �ɾ���㴫�ݸ������������ݶȣ��������㹲��6*12�����ģ��
	outSize.c=cnn->C3->inputWidth;
	outSize.r=cnn->C3->inputHeight;
	nSize inSize={cnn->S4->inputWidth,cnn->S4->inputHeight};
	nSize mapSize={cnn->C3->mapSize,cnn->C3->mapSize};
	for(i=0;i<cnn->S2->outChannels;i++){
		for(j=0;j<cnn->C3->outChannels;j++){
			float** corr=correlation(cnn->C3->mapData[i][j],mapSize,cnn->C3->d[j],inSize,full);
			addmat(cnn->S2->d[i],cnn->S2->d[i],outSize,corr,outSize);
			for(r=0;r<outSize.r;r++)
				free(corr[r]);
			free(corr);
		}
		/*
		for(r=0;r<cnn->C3->inputHeight;r++)
			for(c=0;c<cnn->C3->inputWidth;c++)
				// ���ﱾ�����ڲ����ļ���
		*/
	}

	// C1�㣬�����
	mapdata=cnn->S2->mapSize;
	nSize S2dSize={cnn->S2->inputWidth/cnn->S2->mapSize,cnn->S2->inputHeight/cnn->S2->mapSize};
	// �����Pooling����ƽ�������Է��򴫵ݵ���һ��Ԫ������ݶ�û�б仯
	for(i=0;i<cnn->C1->outChannels;i++){
		float** C1e=UpSample(cnn->S2->d[i],S2dSize,cnn->S2->mapSize,cnn->S2->mapSize);
		for(r=0;r<cnn->S2->inputHeight;r++)
			for(c=0;c<cnn->S2->inputWidth;c++)
				cnn->C1->d[i][r][c]=C1e[r][c]*sigma_derivation(cnn->C1->y[i][r][c])/(float)(cnn->S2->mapSize*cnn->S2->mapSize);
		for(r=0;r<cnn->S2->inputHeight;r++)
			free(C1e[r]);
		free(C1e);
	}	
}

void cnnapplygrads(CNN* cnn,CNNOpts opts,float** inputData) // ����Ȩ��
{
	// �������Ȩ�ص���Ҫ�Ǿ����������
	// �����������ط���Ȩ�ؾͿ�����
	int i,j,r,c;

	// C1���Ȩ�ظ���
	nSize dSize={cnn->S2->inputHeight,cnn->S2->inputWidth};
	nSize ySize={cnn->C1->inputHeight,cnn->C1->inputWidth};
	nSize mapSize={cnn->C1->mapSize,cnn->C1->mapSize};

	for(i=0;i<cnn->C1->outChannels;i++){
		for(j=0;j<cnn->C1->inChannels;j++){
			float** flipinputData=rotate180(inputData,ySize);
			float** C1dk=cov(cnn->C1->d[i],dSize,flipinputData,ySize,valid);
			multifactor(C1dk,C1dk,mapSize,-1*opts.alpha);
			addmat(cnn->C1->mapData[j][i],cnn->C1->mapData[j][i],mapSize,C1dk,mapSize);
			for(r=0;r<(dSize.r-(ySize.r-1));r++)
				free(C1dk[r]);
			free(C1dk);
			for(r=0;r<ySize.r;r++)
				free(flipinputData[r]);
			free(flipinputData);
		}
		cnn->C1->basicData[i]=cnn->C1->basicData[i]-opts.alpha*summat(cnn->C1->d[i],dSize);
	}

	// C3���Ȩ�ظ���
	dSize.c=cnn->S4->inputWidth;
	dSize.r=cnn->S4->inputHeight;
	ySize.c=cnn->C3->inputWidth;
	ySize.r=cnn->C3->inputHeight;
	mapSize.c=cnn->C3->mapSize;
	mapSize.r=cnn->C3->mapSize;
	for(i=0;i<cnn->C3->outChannels;i++){
		for(j=0;j<cnn->C3->inChannels;j++){
			float** flipinputData=rotate180(cnn->S2->y[j],ySize);
			float** C3dk=cov(cnn->C3->d[i],dSize,flipinputData,ySize,valid);
			multifactor(C3dk,C3dk,mapSize,-1.0*opts.alpha);
			addmat(cnn->C3->mapData[j][i],cnn->C3->mapData[j][i],mapSize,C3dk,mapSize);
			for(r=0;r<(dSize.r-(ySize.r-1));r++)
				free(C3dk[r]);
			free(C3dk);
			for(r=0;r<ySize.r;r++)
				free(flipinputData[r]);
			free(flipinputData);
		}
		cnn->C3->basicData[i]=cnn->C3->basicData[i]-opts.alpha*summat(cnn->C3->d[i],dSize);
	}

	// �����
	// ������Ҫ��ǰ��Ķ�ά���չ����һά����
	float* O5inData=(float*)malloc((cnn->O5->inputNum)*sizeof(float)); 
	nSize outSize={cnn->S4->inputWidth/cnn->S4->mapSize,cnn->S4->inputHeight/cnn->S4->mapSize};
	for(i=0;i<(cnn->S4->outChannels);i++)
		for(r=0;r<outSize.r;r++)
			for(c=0;c<outSize.c;c++)
				O5inData[i*outSize.r*outSize.c+r*outSize.c+c]=cnn->S4->y[i][r][c];

	for(j=0;j<cnn->O5->outputNum;j++){
		for(i=0;i<cnn->O5->inputNum;i++)
			cnn->O5->wData[j][i]=cnn->O5->wData[j][i]-opts.alpha*cnn->O5->d[j]*O5inData[i];
		cnn->O5->basicData[j]=cnn->O5->basicData[j]-opts.alpha*cnn->O5->d[j];
	}
	free(O5inData);
}

void cnnclear(CNN* cnn)
{
	// ����Ԫ�Ĳ����������
	int j,c,r;
	// C1����
	for(j=0;j<cnn->C1->outChannels;j++){
		for(r=0;r<cnn->S2->inputHeight;r++){
			for(c=0;c<cnn->S2->inputWidth;c++){
				cnn->C1->d[j][r][c]=(float)0.0;
				cnn->C1->v[j][r][c]=(float)0.0;
				cnn->C1->y[j][r][c]=(float)0.0;
			}
		}
	}
	// S2����
	for(j=0;j<cnn->S2->outChannels;j++){
		for(r=0;r<cnn->C3->inputHeight;r++){
			for(c=0;c<cnn->C3->inputWidth;c++){
				cnn->S2->d[j][r][c]=(float)0.0;
				cnn->S2->y[j][r][c]=(float)0.0;
			}
		}
	}
	// C3����
	for(j=0;j<cnn->C3->outChannels;j++){
		for(r=0;r<cnn->S4->inputHeight;r++){
			for(c=0;c<cnn->S4->inputWidth;c++){
				cnn->C3->d[j][r][c]=(float)0.0;
				cnn->C3->v[j][r][c]=(float)0.0;
				cnn->C3->y[j][r][c]=(float)0.0;
			}
		}
	}
	// S4����
	for(j=0;j<cnn->S4->outChannels;j++){
		for(r=0;r<cnn->S4->inputHeight/cnn->S4->mapSize;r++){
			for(c=0;c<cnn->S4->inputWidth/cnn->S4->mapSize;c++){
				cnn->S4->d[j][r][c]=(float)0.0;
				cnn->S4->y[j][r][c]=(float)0.0;
			}
		}
	}
	// O5���
	for(j=0;j<cnn->O5->outputNum;j++){
		cnn->O5->d[j]=(float)0.0;
		cnn->O5->v[j]=(float)0.0;
		cnn->O5->y[j]=(float)0.0;
	}
}

// �������ڲ��Եĺ���
void savecnndata(CNN* cnn,const char* filename,float** inputdata) // ����CNN�����е��������
{
	FILE  *fp=NULL;
	fp=fopen(filename,"wb");
	if(fp==NULL)
		printf("write file failed\n");

	// C1������
	int i,j,r;
	// C1����
	for(i=0;i<cnn->C1->inputHeight;i++)
		fwrite(inputdata[i],sizeof(float),cnn->C1->inputWidth,fp);
	for(i=0;i<cnn->C1->inChannels;i++)
		for(j=0;j<cnn->C1->outChannels;j++)
			for(r=0;r<cnn->C1->mapSize;r++)
				fwrite(cnn->C1->mapData[i][j][r],sizeof(float),cnn->C1->mapSize,fp);

	fwrite(cnn->C1->basicData,sizeof(float),cnn->C1->outChannels,fp);

	for(j=0;j<cnn->C1->outChannels;j++){
		for(r=0;r<cnn->S2->inputHeight;r++){
			fwrite(cnn->C1->v[j][r],sizeof(float),cnn->S2->inputWidth,fp);
		}
		for(r=0;r<cnn->S2->inputHeight;r++){
			fwrite(cnn->C1->d[j][r],sizeof(float),cnn->S2->inputWidth,fp);
		}
		for(r=0;r<cnn->S2->inputHeight;r++){
			fwrite(cnn->C1->y[j][r],sizeof(float),cnn->S2->inputWidth,fp);
		}
	}

	// S2����
	for(j=0;j<cnn->S2->outChannels;j++){
		for(r=0;r<cnn->C3->inputHeight;r++){
			fwrite(cnn->S2->d[j][r],sizeof(float),cnn->C3->inputWidth,fp);
		}
		for(r=0;r<cnn->C3->inputHeight;r++){
			fwrite(cnn->S2->y[j][r],sizeof(float),cnn->C3->inputWidth,fp);
		}
	}
	// C3����
	for(i=0;i<cnn->C3->inChannels;i++)
		for(j=0;j<cnn->C3->outChannels;j++)
			for(r=0;r<cnn->C3->mapSize;r++)
				fwrite(cnn->C3->mapData[i][j][r],sizeof(float),cnn->C3->mapSize,fp);

	fwrite(cnn->C3->basicData,sizeof(float),cnn->C3->outChannels,fp);

	for(j=0;j<cnn->C3->outChannels;j++){
		for(r=0;r<cnn->S4->inputHeight;r++){
			fwrite(cnn->C3->v[j][r],sizeof(float),cnn->S4->inputWidth,fp);
		}
		for(r=0;r<cnn->S4->inputHeight;r++){
			fwrite(cnn->C3->d[j][r],sizeof(float),cnn->S4->inputWidth,fp);
		}
		for(r=0;r<cnn->S4->inputHeight;r++){
			fwrite(cnn->C3->y[j][r],sizeof(float),cnn->S4->inputWidth,fp);
		}
	}

	// S4����
	for(j=0;j<cnn->S4->outChannels;j++){
		for(r=0;r<cnn->S4->inputHeight/cnn->S4->mapSize;r++){
			fwrite(cnn->S4->d[j][r],sizeof(float),cnn->S4->inputWidth/cnn->S4->mapSize,fp);
		}
		for(r=0;r<cnn->S4->inputHeight/cnn->S4->mapSize;r++){
			fwrite(cnn->S4->y[j][r],sizeof(float),cnn->S4->inputWidth/cnn->S4->mapSize,fp);
		}
	}

	// O5�����
	for(i=0;i<cnn->O5->outputNum;i++)
		fwrite(cnn->O5->wData[i],sizeof(float),cnn->O5->inputNum,fp);
	fwrite(cnn->O5->basicData,sizeof(float),cnn->O5->outputNum,fp);
	fwrite(cnn->O5->v,sizeof(float),cnn->O5->outputNum,fp);
	fwrite(cnn->O5->d,sizeof(float),cnn->O5->outputNum,fp);
	fwrite(cnn->O5->y,sizeof(float),cnn->O5->outputNum,fp);

	fclose(fp);
}
