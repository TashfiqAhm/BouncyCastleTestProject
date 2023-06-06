using EncryptionService;
using EncryptionService.Interface;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<IPgpCoreService,PgpCoreService>();
builder.Services.AddScoped<IBouncyCastleService,BouncyCastleService>();
builder.Services.AddScoped<IBouncyCastleForLargeFileService,BouncyCastleForLargeFileService>();
builder.Services.AddScoped<IPgpCoreService,PgpCoreService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
