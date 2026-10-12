#include <bits/stdc++.h>
using namespace std;

using Board=array<uint16_t,20>;
struct BHash { size_t operator()(Board const&a) const { size_t h=0x9e3779b9; for(auto x:a) h=(h^(x+0x9e37+(h<<6)+(h>>2))); return h; } };
struct Hist { int idx; string cmd; shared_ptr<Hist> prev; Hist(int i,string c,shared_ptr<Hist>p):idx(i),cmd(move(c)),prev(move(p)){} };
struct Node { Board b; shared_ptr<Hist> hist; int score; };

static const char *pat[7][4]={
 {"####............",".#...#...#...#..","####............",".#...#...#...#.."},
 {"##..##..........","##..##..........","##..##..........","##..##.........."},
 {".#..###.........","#...##..#.......","###..#..........",".#..##...#......"},
 {".##.##..........","#...##...#......",".##.##..........","#...##...#......"},
 {"##...##.........",".#..##..#.......","##...##.........",".#..##..#......."},
 {"#...###.........","##..#...#.......","###...#.........",".#...#..##......"},
 {"..#.###.........","#...#...##......","###.#...........","##...#...#......"}
};
vector<pair<int,int>> cells[7][4];

bool collide(Board const&b,int width,int kind,int x,int y,int rot){
 for(auto [dx,dy]:cells[kind][rot]){ int xx=x+dx,yy=y+dy; if(xx<0)return 1; if(yy<0){if(xx>=width)return 1;}else if(xx>=10)return 1; if(yy>=20)return 1; if(yy>=0 && (b[yy]>>xx&1))return 1; } return 0;
}

vector<pair<Board,string>> moves(Board const&b,int kind,int width){
 int mx=0;for(auto [x,y]:cells[kind][0])mx=max(mx,x); int sx=5-(mx+1)/2;
 struct C{int x,y,r;string s;}; vector<C> q{{sx,-2,0,""}}; set<tuple<int,int,int>> seen{{sx,-2,0}};
 for(size_t z=0;z<q.size();z++){
  C c=q[z];
  for(auto [dx,ch]:vector<pair<int,char>>{{-1,'a'},{1,'d'}}){C n{c.x+dx,c.y,c.r,c.s+ch};auto k=make_tuple(n.x,n.y,n.r);if(n.x>=-3&&n.x<=12&&n.y>=-6&&!seen.count(k)&&!collide(b,width,kind,n.x,n.y,n.r)){seen.insert(k);q.push_back(n);}}
  int nr=(c.r+1)&3; int kicks[6][2]={{0,0},{-1,0},{1,0},{0,-1},{-1,-1},{1,-1}};
  for(auto &k:kicks){C n{c.x+k[0],c.y+k[1],nr,c.s+'w'};if(n.y>=-6&&!collide(b,width,kind,n.x,n.y,n.r)){auto t=make_tuple(n.x,n.y,n.r);if(!seen.count(t)){seen.insert(t);q.push_back(n);}break;}}
 }
 unordered_map<Board,string,BHash> out;
 for(auto c:q){if(collide(b,width,kind,c.x,c.y,c.r))continue;while(c.y+1<20&&!collide(b,width,kind,c.x,c.y+1,c.r))c.y++;if(c.y<0)continue;Board n=b;for(auto [dx,dy]:cells[kind][c.r])n[c.y+dy]|=1u<<(c.x+dx);out.emplace(n,c.s+'.');}
 vector<pair<Board,string>> v;for(auto &x:out)v.push_back(x);return v;
}

vector<pair<Board,string>> moves_pressure(Board const&b,int kind,int width){
 if(kind!=0)return moves(b,kind,width);
 vector<pair<Board,string>> out;
 // With pressure latched, rotating at spawn would invoke the bug.  Horizontal
 // hard drops remain ordinary legal placements.
 for(int x=0;x<=6;x++){
  int y=-2;if(collide(b,width,kind,x,y,0))continue;
  while(y+1<20&&!collide(b,width,kind,x,y+1,0))y++;
  if(y<0)continue; Board n=b;for(auto [dx,dy]:cells[kind][0])n[y+dy]|=1u<<(x+dx);
  string c=(x<3?string(3-x,'a'):string(x-3,'d'))+".";out.push_back({n,c});
 }
 return out;
}

int eval(Board const&b){
 int sumh=0,top=0,row1=__builtin_popcount(b[1]),bump=0;int hs[10];
 for(int x=0;x<10;x++){int y=0;while(y<20&&!(b[y]>>x&1))y++;hs[x]=20-y;sumh+=hs[x];}for(int x=0;x<9;x++)bump+=abs(hs[x]-hs[x+1]);top=__builtin_popcount(b[0]);
 int holes=0;for(int x=0;x<10;x++){bool seen=false;for(int y=0;y<20;y++){if(b[y]>>x&1)seen=true;else if(seen)holes++;}} return -(120*sumh+900*top+800*row1+500*holes+20*bump);
}

int main(int argc,char**argv){
 for(int k=0;k<7;k++)for(int r=0;r<4;r++)for(int y=0;y<4;y++)for(int x=0;x<4;x++)if(pat[k][r][4*y+x]=='#')cells[k][r].push_back({x,y});
 int N=argc>1?atoi(argv[1]):10000, BW=argc>2?atoi(argv[2]):1000;
 int START=argc>3?atoi(argv[3]):8407, GROW=argc>4?atoi(argv[4]):8432;
 int LATCH=argc>5?atoi(argv[5]):-1;
 vector<int> seq(N);for(int i=0;i<N;i++)seq[i]=rand()%7;
 Board initial={};
 vector<Node> beam{{initial,nullptr,eval(initial)}}; int lastclear=-1;
 for(int idx=START;idx<N;idx++){
  if(idx==LATCH){
   vector<Node> latched;
   for(auto &n:beam){
    int occupied=0; for(auto row:n.b) occupied+=__builtin_popcount(row);
    if(seq[idx]==0 && occupied>=60)
     latched.push_back(Node{n.b,make_shared<Hist>(idx,"LATCH",n.hist),n.score});
   }
   beam=move(latched);
   if(beam.empty()){cerr<<"could not latch at "<<idx<<"\n";return 2;}
   continue;
  }
  if(seq[idx]==0 && idx>=GROW){for(auto &n:beam)n.hist=make_shared<Hist>(idx,"EVIL",n.hist);continue;}
  unordered_map<Board,Node,BHash> mp; vector<Node> cleared;
  for(auto const&n:beam)for(auto &[nb,cmd]:(LATCH>=0 && idx<LATCH ? moves(n.b,seq[idx],10) : moves_pressure(n.b,seq[idx],10))){
   bool cl=false;
   bool reject=false; for(int y=0;y<20;y++)if(nb[y]==0x3ff){
    // Before the forced latch, retain pressure by avoiding line clears.  After
    // the malicious interval starts, avoid memmove with the corrupted stride.
    if(idx>=GROW || (LATCH>=0 && idx<LATCH)){reject=true;break;}
    for(int z=y;z>0;z--)nb[z]=nb[z-1]; nb[0]=0; cl=true;
   } if(reject)continue;
   Node z{nb,make_shared<Hist>(idx,cmd,n.hist),eval(nb)};
   if(cl)cleared.push_back(move(z)); else {auto it=mp.find(nb);if(it==mp.end()||z.score>it->second.score)mp[nb]=move(z);}
  }
  if(!cleared.empty()){
   auto cost=[](Node const&n){int c=0;for(auto r:n.b)c+=__builtin_popcount(r);return c;};
   sort(cleared.begin(),cleared.end(),[&](auto&a,auto&b){if(cost(a)!=cost(b))return cost(a)<cost(b);return a.score>b.score;});
   vector<Node> nv;nv.reserve(mp.size());for(auto &x:mp)nv.push_back(move(x.second));
   sort(nv.begin(),nv.end(),[](auto&a,auto&b){return a.score>b.score;});
   int kc=min((int)cleared.size(),max(1,BW*3/4)), kn=min((int)nv.size(),BW-kc);
   cleared.resize(kc);for(int i=0;i<kn;i++)cleared.push_back(move(nv[i]));beam=move(cleared);lastclear=idx;
  }else{
   vector<Node> nv;nv.reserve(mp.size());for(auto &x:mp)nv.push_back(move(x.second));
   sort(nv.begin(),nv.end(),[](auto&a,auto&b){return a.score>b.score;});if((int)nv.size()>BW)nv.resize(BW);beam=move(nv);
   if(beam.empty()){cerr<<"died at "<<idx<<" lastclear "<<lastclear<<"\n";return 1;}
  }
 }
 cerr<<"done, lastclear "<<lastclear<<" states "<<beam.size()<<"\n";
 vector<pair<int,string>> ans; for(auto h=beam.front().hist;h;h=h->prev)ans.push_back({h->idx,h->cmd}); reverse(ans.begin(),ans.end());
 cout<<"# session "<<START<<" grow "<<GROW<<"\n";for(auto &[i,s]:ans)cout<<i<<" "<<s<<"\n";
}
