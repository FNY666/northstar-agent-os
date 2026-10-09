"""z_42: matmul2."""
from __future__ import annotations
VERSION = "z_42.v1"
def matmul2(A,B):
    return [[A[0][0]*B[0][0]+A[0][1]*B[1][0],A[0][0]*B[0][1]+A[0][1]*B[1][1]],[A[1][0]*B[0][0]+A[1][1]*B[1][0],A[1][0]*B[0][1]+A[1][1]*B[1][1]]]

def main() -> None:
    assert matmul2([[1,2],[3,4]],[[2,0],[1,2]])==[[4,4],[10,8]]
    assert matmul2([[1,0],[0,1]],[[5,6],[7,8]])==[[5,6],[7,8]]
    print('z_42 matmul2 OK')

if __name__ == "__main__": main()
