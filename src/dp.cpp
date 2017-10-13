#include<stdio.h>
#include<iostream>
using namespace std;
int arr[] = {1, 2, 3};
int m = 3;
// Returns the count of ways we can sum  S[0...m-1] coins to get sum n
int func( int  n)
{
    int sum = 0;
    if(n==0)
        return 1;
    if (n<0)
        return 0;
    for(int i=0;i<m;i++)
        sum+=func(n-arr[i]);
    return sum;
}

// Driver program to test above function
int main()
{
    int i, j;
    cout<<"Selina is crazy"<<endl;
    cout<<endl;
    cout<<func(4)<<endl;
    getchar();
    return 0;
}
