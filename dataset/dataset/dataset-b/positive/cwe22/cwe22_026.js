const fs=require('fs');
const path=require('path');
const express=require('express');
const app=express();

app.get('/download',(req,res)=>{
  const file=req.query.file;
  const filePath=path.join(__dirname,'files',file);
  fs.readFile(filePath,(err,data)=>{
    if(err)return res.status(404).send('File not found');
    res.set('Content-Type','application/octet-stream');
    res.send(data);
  });
});

app.listen(3000);