function playaudio(color){
    switch(color){
        case "green":
            var audio = new Audio("sounds/green.mp3");
            audio.play();
            break;
        case "red":
            var audio = new Audio("sounds/red.mp3");
            audio.play();
            break;
        case "yellow":
            var audio = new Audio("sounds/yellow.mp3");
            audio.play();
            break;

        case "blue":
            var audio = new Audio("sounds/blue.mp3");
            audio.play();
            break;

        case "wrong":
            var audio = new Audio("sounds/wrong.mp3");
            audio.play();
            break;

        default:console.log("K");
    }
}

function animatePress(color){
    $("#"+color).addClass("pressed");
    $("#"+color).css("background-color","gray");
    setTimeout(function(){
        $("#"+color).removeClass("pressed");
        $("#"+color).css("background-color",color);
    },200);
}

function addtoSequence(){
    var randomNumber = Math.floor(Math.random()*4);
    randomColor = randomColors[randomNumber];
    sequence.push(randomColor);
}

function showNewOne(){
    playaudio(sequence[sequence.length-1]);
    animatePress(sequence[sequence.length-1]);
}

function resetSequence(){
    sequence = [];
    i = 0;
    addtoSequence()
    showNewOne();
}


var start = false;
var sequence = [];
var i;
var currentColor;
var randomColor;
var randomColors = ["green","red","yellow","blue"];
var line;

addEventListener("keydown",function(event){
    if(!start){
        start = true;
        $("h1").text("Level 1");
        resetSequence();
    }
});

document.addEventListener("touchstart", function(event) {
    if(!start){
        start = true;
        $("h1").text("Level 1");
        resetSequence();
    }
  });

$(".btn").click(function(){
    if(start){
        currentColor = $(this).attr("id");
    
        if(currentColor === sequence[i]){
            animatePress(currentColor);
            playaudio(currentColor);
            i++;

            if(i===sequence.length){
                i = 0;
                addtoSequence();
                $("h1").text("Level "+(sequence.length));
                setTimeout(function(){
                    showNewOne();
                },1000);
            }
        }

        else{
            if(sequence.length < 6){
                line = " Game over! Pathetic! ";
            }
            if(sequence.length > 5 && sequence.length < 10){
             line = " Sounds like a skill issue! ";
            }
            if(sequence.length > 9){
             line = " That was acceptable! ";
            }
            $("h1").text(line +"Press any key to restart");
            playaudio("wrong");
            start = false;
        }
    }
    
});
