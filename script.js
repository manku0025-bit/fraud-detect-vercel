function scan(){

let msg=document.getElementById("msg").value

fetch("/scan",{
method:"POST",
headers:{
"Content-Type":"application/x-www-form-urlencoded"
},
body:"message="+msg
})
.then(res=>res.text())
.then(data=>{
document.getElementById("result").innerHTML=data
})

}