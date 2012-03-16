import cairo # import the Python module
 
# setup a place to draw
surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, 800, 800)
ctx = cairo.Context (surface)
 
# paint background

minheight = 100;
minwidth = 10;
padding = 5;
margin = 50;
 
# draw text
ctx.set_source_rgb(0.0, 0.0, 0.0) # yellow
ctx.select_font_face('Sans')
ctx.set_font_size(14) # em-square height is 90 pixels

def drawmodule(ctx, name, inputs, outputs):
	m = 2
	(x_bearing, y_bearing, twidth, theight, x_advance, y_advance) = ctx.text_extents(name)

	width = max(minwidth, twidth + padding*2)
	height = max(minheight, theight+2*padding)

	ctx.set_source_rgb(0.0, 0.0, 0.0) # blue
	ctx.rectangle(margin, margin, width, height)
	ctx.set_line_width( 1.5 )
	ctx.stroke()
	
	ctx.set_line_width( 1.0 )
	ctx.move_to(margin+padding, margin+padding+theight) # move to point (x, y) = (10, 90)
	ctx.show_text(name)
	
	ctx.move_to(padding, margin+padding+theight)
	
 
drawmodule(ctx, 'Block', ['a', 'b'], ['c'])
drawmodule(ctx, 'Block Module', ['a', 'b'], ['c']) 
 
# finish up
ctx.stroke() # commit to surface
surface.write_to_png('hello_world.png') # write to file

