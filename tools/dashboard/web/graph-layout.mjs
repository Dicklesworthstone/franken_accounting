// Bounded deterministic spring/repulsion/collision layout. Visual coordinates only.
// No accounting amount is inspected or converted to a float here.
export function layoutGraph(graph) {
  if (graph.nodes.length > 220 || graph.edges.length > 600) throw new Error('Graph display bound exceeded.');
  const nodes = graph.nodes.map((node,i)=> {
    const angle = (i + .5) * 2.399963229728653;
    const radius = node.root ? 0 : 170 + Math.sqrt(i+1)*55;
    return {...node,x:Math.cos(angle)*radius,y:Math.sin(angle)*radius*.72,vx:0,vy:0,fixed:!!node.root};
  });
  const byId = new Map(nodes.map(n=>[n.id,n]));
  const edges = graph.edges.map(edge=> {
    const source=byId.get(edge.source),target=byId.get(edge.target);
    if (!source || !target) throw new Error('Missing graph endpoint.');
    return {...edge,source,target};
  });
  let alpha = 1;
  return {nodes,edges,get active(){return alpha>.015;},reheat(){alpha=.8;},
    step(iterations=1) {
      if (!Number.isInteger(iterations) || iterations<1 || iterations>1000) throw new Error('Invalid layout iteration count.');
      for(let iter=0;iter<iterations&&alpha>.015;iter++) {
        for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++) {
          const a=nodes[i],b=nodes[j];let dx=b.x-a.x,dy=b.y-a.y;
          if(Math.abs(dx)+Math.abs(dy)<.001){dx=(i%2?.1:-.1);dy=.1;}
          const distance=Math.max(30,Math.hypot(dx,dy));
          const force=Math.min(10,9000/(distance*distance))*alpha;
          const fx=dx/distance*force,fy=dy/distance*force;
          a.vx-=fx;a.vy-=fy;b.vx+=fx;b.vy+=fy;
          // Card-sized collision boxes, independent of zoom/labels/amounts.
          const ox=168-Math.abs(dx),oy=84-Math.abs(dy);
          if(ox>0&&oy>0){
            if(ox<oy){const shift=(dx<0?-1:1)*ox*.24;a.vx-=shift;b.vx+=shift;}
            else{const shift=(dy<0?-1:1)*oy*.24;a.vy-=shift;b.vy+=shift;}
          }
        }
        for(const edge of edges){
          const a=edge.source,b=edge.target,dx=b.x-a.x,dy=b.y-a.y,d=Math.max(1,Math.hypot(dx,dy));
          const force=(d-220)*.018*alpha;
          a.vx+=dx/d*force;a.vy+=dy/d*force;b.vx-=dx/d*force;b.vy-=dy/d*force;
        }
        for(const node of nodes){
          if(node.fixed){node.vx=node.vy=0;continue;}
          node.vx=(node.vx-node.x*.0015*alpha)*.73;
          node.vy=(node.vy-node.y*.0015*alpha)*.73;
          node.x+=Math.max(-16,Math.min(16,node.vx));node.y+=Math.max(-16,Math.min(16,node.vy));
          if(!Number.isFinite(node.x)||!Number.isFinite(node.y))throw new Error('Nonfinite graph geometry.');
        }
        alpha*=.977;
      }
    }
  };
}
export function graphBounds(nodes) {
  if(!nodes.length)return {x:-300,y:-200,width:600,height:400};
  const minX=Math.min(...nodes.map(n=>n.x))-130,maxX=Math.max(...nodes.map(n=>n.x))+130;
  const minY=Math.min(...nodes.map(n=>n.y))-100,maxY=Math.max(...nodes.map(n=>n.y))+100;
  const width=Math.max(500,maxX-minX),height=Math.max(340,maxY-minY);
  return {x:(minX+maxX-width)/2,y:(minY+maxY-height)/2,width,height};
}
