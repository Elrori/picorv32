module SB_IO #(
    parameter PIN_TYPE = 6'b1, 
    parameter PULLUP = 1'b0
) (
    inout       PACKAGE_PIN  ,
    input       OUTPUT_ENABLE,
    input      D_OUT_0      ,
    output      D_IN_0       
);
assign D_IN_0 = PACKAGE_PIN;
assign PACKAGE_PIN = (OUTPUT_ENABLE)? D_OUT_0 : 1'bz;
endmodule