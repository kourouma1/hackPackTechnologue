import random

model1 = """ .;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;.    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX$$$$$$$$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX$&$xxXXXxxxX&$XXXXXXXXXXXXX$$$$$$&&&&&&$$$$$$$$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXXX$$x+xX$XXXXXXxXX$$XXXXXXXXXXXx++;;:::::::::;;;+xX$&&&&&&&&&&$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXX$$xXX$XxxxXXXXXXXx$XXXXXXXXXXX$$$$$&&&&&&&&&&$X+;:::::::::::+X&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXX$+xXXXXXXXXXXXXxxxx$XXXXXXXXXXXXXXXXXX$$$$$&&&&&&&&&&&&&&&&$;::$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXX$$XXXXX$&&&&&&$$XXXX$XXXXXXXXX$$&&&&&$$X+;;::::::::::;;xxx+::X+:X&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXX$XXX&$Xx++xXXXXX$$XXX$XXXXXXXXX+:::::;+X$$$&&&&&&&&&&$;:::::;x&::x&$$XXXXX$$&$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXX$$x$&&$&&&$x;;;;x$$&&&XX$XXXXXXX$$&&&&&$$$XX$$&&&$;::::+$&&&&&&$$&$::X&&&&&&$;:;&&$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXX$XX$$$x+xX&x&$+&&&$+x+X&XX$XXXXXXXXXXXXXXX$$$$+:::;X&&&&&$$XXXXXX$&&X;:::::::+&&&x:;&&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXx&$$$X+++:;+X.X+;++++$$$XX$XXXXXXXXXXXXXXX::X$&&&$$XXXXXXXXXXX$&$::::;X&&&$x;::::$&:;&&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXX$X+&$$$&++;:X;; .;x.::+$$$X$&&&&&&&&&&&&&&&&&&&&&&&&&&&&$XXXXXX$&;:;:X&&&$X$$$&&&&$+::X:;&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXx$$$$$++x+X&&&&&++XXX&$$X&                           &&XXXXXX$X;+;$&$XXXXXXXXXXX$$&&;:::$&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXX$XX$$$$&$;&X+x+++X$++$$$$X&&&&&&&&&&&&&&&&&&&&&&&&&&&; &XXXXXX$+;++&$XXXXXXXXXXXXXXX$&&&;:X&&$XXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXX$XX$$$$$&&&$;XXX;&$&&$$$xXXXXXXXXXX$$&&&&$$XXXXXXXXX&X &XXXXXX$+;+;&$XXXXXXXXXXXXXXXXXX$&&+::XXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXX$XX$$$&$X&&&&$&$&&$$$$XX$XXXXXXXX$X;++++;$XXXXXXXXX&X &XXXXXX$X;;;;&&$XXXXXXXXXXXXXXXXXX$$&&$XXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXX$$$Xx$$$x+++xX$&&$XXX$$$x$$$&$$XXXX$+:$;+X:$XXXXXXXXX&X &XXXXXX$&+:;;:X&&&&&$$$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXX$$$$$$$XxX$&&&&&&&&&&&&&&&&XXXXxX$$XXX$$&&;x&&$XXXXXXXXX&X &XXXXXXX$&&;::::::;+XX$&&&&&&&&&&&$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXX&&&&&&&&$&&&$        .     :&&&XXx+X$$XXXX$:::;$XXXXXXXXXX&x &XXXXXXXXX$&&&$X+;::::::::::::;:::;xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXx++X$ :&&&   $&&&&&&&&&&&&&   &&X$&&&&&&&&&&&&&&&&&&&&&&&&&+ &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&$XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXX$$$&       &&&+:::::::::::&&&  &&&       &     :&     &&  &&  &  ;&&  &$     &$  &XX&&     $&:    ;&  +&. :&      &XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXX&&&&&& :&X$x;;&$;;X&+;;&X&X    $$$ :&$&  &&X&. ;&:  &  &&  &.  $&  &  &&; ;&  &XX&  X&$  &  &&  &: X&: +&  &&X$&XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXX$$XXX&& .&X$+::&X;;X&;::&X&x &&&&&& ;&&& :&&&&; X&&&&&  &&  &:   &  &  &&X x&  &X$&  &&& .&  &&&&&; $&; x&  &&&&$XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXX$&&&&&&&& .&X$$&&&X;;x&$&&$X&x    &&& :&&&     &; +&&&&&      &: $    &  &&+ x&  &X$&  $&& .&  &   &; $&; +&     &XXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXX$  .       &XXXXX$X;;x&XXXXX&x &&&&&& :&&& x&&&&+ &&&  &  &&  &: &$   &  &&& x&  &&&&: &&& .& ;&&; &; &&& +&  &&&&&XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXX$&$;&&&&&$+&XXXX$&$;;X&$XXXX&X    $&+  &$&     :       &  &$  &  +&   &      :&     :       &      &      .$      &XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXX$&&&&  :  &$XXX&:;;;;:&XXXX&X &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&XXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXX&X &&  &&&&&&+xxxx+&&&&&&  $                                  $X$$XX$$$$$XX$$$$$XX$$$$$XXXX$$$XXX$$$$$XXX$$$XXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXX&&  &&&    :+++xXx$x++;    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXX&    &&&&&&$ XX &; &x $$&&&&XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXX&&&&&$XXX$&X && &  &+ &&$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX$&&&&&&&&&&&&XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    .;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;. """


model2 = """ ::::::::::::::::::::::::::.:.:..:.::::::::::::::::::::::::::::::::::::::::::::::::::::::::::;;;;;;;;;     
    :XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX$$$XXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&.&&$$$$XXXXXXXXXXXXX;    
    :XXXXXXXXXXXXXXXXXXXXXXXXXXXX$&&$$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX$&&&&$XXX$&&..&&+ $XXXXXXXXXXXXX;    
    :XXXXXXXXXXXXXXXXXX$$&&&&&&&X;:.;+$&&&&$$XXXXXXXXXXXXXXXXXXXXXXXXXXX&&&   :&&&&X;:    $&&$XXXXXXXXXXXX;    
    :XXXXXXXXXXXXX$&&&&X;....:::;;+++;;:::::;x$$$$$$XXXXXXXXXXXXXXXXXXX&$  +X+:..  ......:. :$XXXXXXXXXXXX;    
    :XXXXXXXXXXXX$+ :::;;+xx+++++++++++++++++;;;;::+XXXXXXXXXXXXXXXXXXX& +&&$$&&&&&$$$&$.&&&&$XXXXXXXXXXXX;    
    :XXXXXXXXXXXX&:;x++xX$$$$$$X++++++++x$$&&&&&$Xx;$XXXXXXXXXXXXXXX$&&&.;$XXXXXXXX$$$$&$$XXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&:;+++$       $$Xx+++X$$X      :x+;$XXXXXXXXXXXXXXxx: ;x$$X$x+XXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&:;+++$ .....   ;&$$$$   .:::: &&+;$XXXXXXXXXXXX$$XX+;+X$$&&&&XXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&;;+++$ ...        x   ..   :: $&+;$XXXXXXX$$$&$XXXXXXXX+++++x$&$$XXXXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&;;x++$ ..  &+     ..:    & :: $&x+$XXXXX$&$xx++++++++++++++;;:::X$$XXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&;;x++$ ..  &&&&   :.  $&&& :: $&x+$XXX$$+++;;::::::;;;+++xXXX$$Xx;+XXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&;;x++$ .:  &;+X&& :. &&$X& :: $&x+$XX$+++;:::::::;;;;++++xxxXXXXXXXXXXXXXXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX&;;x++$ .:. &+++$: :: &x+x& :: $&x+$$$$$$X+;;;;;;;;++xXX$$$$$$$$$$XXXXXXXXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXX&;;x++$ .:. &+++$: :: &++x& :: X&x+$$    ..:::;;;;;;;;:  ..::;;;+X$$$$$$XXXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXX$+:+++$  .. &+++X     &++x& :  X$+X&x.:&+& &&:&.X&+$;+;$&&+++++xxxxxxXx$$XXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXX$$X;++X&:   &;++X$&&&&&x+X&   $&X+$XX:;&$;X:&::&X.X$::&+:.&;+&&;$$X&xXX$$XXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXX$$+;+X$&  &++xx+++++xxxxX  &&Xx$$X;. ; :$ +$:&:;$&++&&++&;&$&XXx+$+XX$$XXXXXXXXXXXXXXXX;    
    ;XXXXXXXXXXXXXXX$$$;++X&&&++xxxxx+xxxxx$&&&+$$XXX+xx+;;::..           ::::;+Xx&&+xXX$$XXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXXXXXXX$&$+;;+xxxxxxxxxxxxxx+;+$$XXXXX$$$&&&&&&&&&&&&&&&&&&&&&&&$$$XXXXX$$$XXXXXXXXXXXXXXXX;    
    :XXXXXXXXXXXXXXXXXXXX$&X;++xxxxxxxxx++++&XXXXXXXX$XXXXXXXXXXXXXXXXXXXXXX$$$$$$$$$$$$&xXXXXXXXXXXXXXXXX:    
    :XXXXXXXXXXXXXXXXXXXXxxX$&X+++xxxx+++$$XXxxxXXXXxx$$$XXXXXXXXXXXXXX$X$X$$$$$$$$$$$$&xxXXXXXXXXXXXXXXXX:    
    :XXxXXxXXXXXXXXxxxxxxxXxxxX$&X++++$$XxxxxXXXXXXXXXxX$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$&+xxXXXXXXXXXXXXXXXX:    
    .xXXXXXXXXXxXxXXXXXXXXXXXXXxxXX$$XXXXXX$$$$$$$&$&$$$X$&$$$$$$$$$$$$$$$$$$$$$$$$$&++xXXXXXXXXXXXXXXXXXX:    
    .XXXXXXxXXXXXXXXXX$X$$$$&&&&&&&&&&&&&&&&&&$$$XXXXxxxx++X&$$$$$$$$$$$$$$$$$$$$$$xXXXXXXXXXXXXXXXXXXXXXX:    
    .XXxxxxxxxxxxxxxx++++++++++;;;;;;;;;;;;;;++++++xxxxXXXXXXX$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ """
    
model3 ="""                                                                                                              
                                                 .:;+xXXx+;.                                                   
                                            +$$$$$$$$$$$$$$$$$$$x                                              
                                         ;$$$X+++++++++++++++++X$$$;                                           
                                        $$X+++++++++++++++++++++++X$$                                          
                                       +$x+++++++++++++++++++++++++x$$                                         
                                      :$x+++++++++++++++++++++++++++XX                                         
                                       $++++++++++++++++++++++++++++X$                                         
                                       $+++++xXXXXx+++++++xXXXXx++++XX                                         
                                      .$x++X$$$xx$$$x+++x$$$XxX$$X++XX                                         
                                       +X+X$:      +$x++XX       $Xx$X                                         
                                       :$x$         +X++$         $XX                                          
                                        +$$         +X++$         $$:                                          
                                         +$$X      x$$$$$$      +$$X                                           
                                          +X$$$$$$$$$   $$$$$$$$$$;                                            
                                         +$Xx+++++X$     $++++++X$                                             
                                          +$$$$X++$      $+xX$$$$$                                             
                                              x$$XX; x$  Xx$$                                                  
                                  X+x+.          $$$$X$$$$$+            ++X                                    
                                 $$$$$$+       :$   XXXXX:   X        X$$$$$x                                  
                                 Xx+++XX        $$X+;;;;:;X$$x        $x+++X:                                  
                              $$$X++++xX$X      $$$XxxxxXXX$$$      :$X++++x$$$X                               
                              $$XXXXXXXxx$$$$     $$$$$$$$$x     +$$$XxXXXXXXX$$                               
                               :$$$$$$$$$$XxX$$$              $$$$Xx$$$$$$$$$$;                                
                                         ;$$$XxX$$$+      :X$$$xX$$$+                                          
                                            ;+$$$XX$$$x:$$$XxX$$$+                                             
                                                :Xx++xX$Xx++X+.                                                
                                                 ;+++++++++++:                                                 
                                              $$$$xx$$$$$$$xx$$$$                                              
                                          ;$$$XxX$$$$     $$$$XxX$$$.                                          
                                      :$$$$XxX$$$x           +$$$XxX$$$$X+$$$$$                                
                               .$$$$$$$X+x$$$$:                 :X$$X++xXXX++x$$                               
                               X$$Xx+++xX$X                        :$$x++++X$$$;                               
                                .:+++++XX                            +$x++x$                                   
                                  $X++x$;                             X$$$$$                                   
                                   $$$$$.                                                                      
                                 X:       xX;+x .$+;  +xX   $$:+  X;+XX+ ;;+XX.                                
                                  $$::$$x  $;$$  +$$$ X$  $$+ ;$  $$$ x$ X$$  $$$                              
                                  $$  +$x X$:$$+  + $$X$ .$$. X$X $x$:   ;X$X$$;                               
                                 $$$$$$X $$$ $$$$$$: $$$  +$$$$$  $$$$$$:$$$X $$$                              
                                                                                                               
                                                                                                               """
                                                                                                               
                                                                                                               
                                                                                                               
models = [model1, model2, model3]

def get_models():
    choix = random.choice(models)
    return choix